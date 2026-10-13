import { describe, expect, it, vi } from 'vitest';
import { OperatorAgent } from '../operators/index.js';
import type { LLMBackbone } from '../llm/index.js';
import { CheckpointRestoreError, CheckpointWriteError, UnsafeResumeError, validateTaskDecomposition } from '../agent/checkpoint.js';
import { KillChainPhase, type Target, type Task } from '../types/index.js';

const target = { id: 'target', address: 'https://fixture.test' } as Target;
const task = (): Task => ({ id: 'parent', missionId: 'mission', name: 'Parent', description: 'Check fixture.test',
  phase: KillChainPhase.RECON, operatorType: 'recon', status: 'in_progress', priority: 1, dependencies: [], createdAt: 1 });
const plan = JSON.stringify([{ name: 'First', description: 'Read first fixture' }, { name: 'Second', description: 'Read second fixture' }]);
function fixture(id?: string) {
  const prompt = vi.fn().mockResolvedValue(plan);
  const operator = new OperatorAgent('Fixture', 'recon', { cooldownMs: 0, maxRetries: 3 }, { prompt } as unknown as LLMBackbone, id);
  return { operator, prompt };
}

describe('persistent decomposed task queues', () => {
  it('restores the remaining child after interruption without repeating the parent, completed children or the decomposition request', async () => {
    const parent = task(); const first = fixture(); let saved = '';
    const executed: string[] = [];
    first.operator.setCheckpointWriter(async () => { saved = JSON.stringify({ parent, operator: first.operator.exportCheckpoint() }); });
    first.operator.executeTask = async (child, _target, signal) => {
      executed.push(child.id);
      if (child.id === parent.id) throw new Error('Split this operation');
      if (child.id.endsWith('-0')) return { success: true, output: 'First evidence', findings: ['First finding'] };
      return new Promise((_resolve, reject) => signal?.addEventListener('abort', () => reject(signal.reason), { once: true }));
    };
    const pending = first.operator.assignTask(parent, target);
    await vi.waitFor(() => expect(executed).toHaveLength(3));
    expect(first.operator.isAvailable()).toBe(false);
    expect(first.operator.state.currentTask).toBe(parent.id);
    first.operator.abortActiveTask('pause'); expect((await pending).error).toContain('aborted:');
    const restored = JSON.parse(saved) as { parent: Task; operator: ReturnType<OperatorAgent['exportCheckpoint']> };
    expect(restored.parent.decomposition?.tasks[0]).toMatchObject({ status: 'completed', result: { output: 'First evidence' } });
    const second = fixture(first.operator.id); second.operator.restoreCheckpoint(restored.operator);
    const execute = vi.fn().mockResolvedValue({ success: true, output: 'Second evidence', findings: ['Second finding'] });
    second.operator.executeTask = execute;
    const result = await second.operator.assignTask(restored.parent, target);
    expect(second.prompt).not.toHaveBeenCalled(); expect(execute).toHaveBeenCalledOnce();
    expect(execute.mock.calls[0][0].id).toBe('parent-decomp-1');
    expect(result.output).toBe('First evidence\n---\nSecond evidence');
    expect(result.findings).toEqual(['First finding', 'Second finding']);
  });

  it('saves the failure before asking for a decomposition and never retries parent execution after a planning interruption', async () => {
    const parent = task(); const first = fixture(); let saved = '';
    first.operator.setCheckpointWriter(async () => { saved = JSON.stringify(parent); });
    first.operator.executeTask = vi.fn().mockRejectedValue(new Error('Original failure'));
    first.prompt.mockImplementation((_text, _system, options: { signal: AbortSignal }) => new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(options.signal.reason), { once: true });
    }));
    const pending = first.operator.assignTask(parent, target);
    await vi.waitFor(() => expect(first.prompt).toHaveBeenCalledOnce());
    first.operator.abortActiveTask('planning pause'); await pending;
    const restored = JSON.parse(saved) as Task;
    expect(restored.decomposition).toEqual({ version: 1, phase: 'planning', reason: 'Original failure', tasks: [] });
    const next = fixture(); const execute = vi.fn().mockResolvedValue({ success: true, output: 'Child evidence' });
    next.operator.executeTask = execute; await next.operator.assignTask(restored, target);
    expect(next.prompt).toHaveBeenCalledOnce(); expect(execute).toHaveBeenCalledTimes(2);
    expect(execute.mock.calls.every(([child]) => child.id !== parent.id)).toBe(true);
  });

  it('refuses to execute children when publishing their queue fails', async () => {
    const parent = task(); const f = fixture();
    const execute = vi.fn().mockRejectedValue(new Error('Original failure')); f.operator.executeTask = execute;
    f.operator.setCheckpointWriter(async current => { if (current.decomposition?.phase === 'executing') throw new Error('disk full'); });
    await expect(f.operator.assignTask(parent, target)).rejects.toBeInstanceOf(CheckpointWriteError);
    expect(execute).toHaveBeenCalledOnce(); expect(f.operator.isAvailable()).toBe(true);
  });

  it('propagates unsafe child recovery without decomposing or executing additional work', async () => {
    const parent = task(); const f = fixture();
    f.operator.executeTask = async child => {
      if (child.id === parent.id) throw new Error('Original failure');
      throw new UnsafeResumeError({ id: 'unsafe', name: 'http_request', arguments: { method: 'POST' } });
    };
    await expect(f.operator.assignTask(parent, target)).rejects.toBeInstanceOf(UnsafeResumeError);
    expect(f.prompt).toHaveBeenCalledOnce(); expect(parent.decomposition?.tasks[1].status).toBe('pending');
  });

  it('validates all child contracts before allowing any restored queue to execute', async () => {
    const parent = task(); const f = fixture();
    f.operator.executeTask = async child => { if (child.id === parent.id) throw new Error('Split'); return { success: true }; };
    await f.operator.assignTask(parent, target);
    const corrupt = structuredClone(parent); if (!corrupt.decomposition) throw new Error('Missing tree');
    corrupt.decomposition.tasks[1].phase = KillChainPhase.EXPLOIT;
    const next = fixture(); const execute = vi.fn(); next.operator.executeTask = execute;
    await expect(next.operator.assignTask(corrupt, target)).rejects.toBeInstanceOf(CheckpointRestoreError);
    expect(execute).not.toHaveBeenCalled();
    expect(() => validateTaskDecomposition(corrupt, target)).toThrow(CheckpointRestoreError);
  });

  it('bounds recursive decomposition even if a caller configures excessive retries', async () => {
    const parent = task(); const f = fixture(); f.operator.config.maxRetries = 100;
    f.operator.executeTask = vi.fn().mockRejectedValue(new Error('Always fails'));
    await f.operator.assignTask(parent, target);
    // Two children per level: root + 2 + 4 + 8, with no fourth-level plan.
    expect(f.operator.executeTask).toHaveBeenCalledTimes(15); expect(f.prompt).toHaveBeenCalledTimes(7);
    validateTaskDecomposition(parent, target);
  });

  it('restores the persisted child cooldown before executing the remaining work and stays unavailable during the wait', async () => {
    const parent = task(); const f = fixture();
    f.operator.executeTask = async child => { if (child.id === parent.id) throw new Error('Split'); return { success: true }; };
    await f.operator.assignTask(parent, target);
    const restored = structuredClone(parent); if (!restored.decomposition) throw new Error('Missing tree');
    const remaining = restored.decomposition.tasks[1]; remaining.status = 'pending'; delete remaining.result;
    restored.decomposition.cooldownUntil = Date.now() + 200;
    const next = fixture(); next.operator.config.cooldownMs = 1000;
    const waits = vi.fn(); next.operator.on('cooldown:started', waits);
    const execute = vi.fn().mockResolvedValue({ success: true }); next.operator.executeTask = execute;
    const pending = next.operator.assignTask(restored, target);
    await vi.waitFor(() => expect(waits).toHaveBeenCalled());
    expect(execute).not.toHaveBeenCalled(); expect(next.operator.isAvailable()).toBe(false);
    expect(waits.mock.calls[0][0].durationMs).toBeGreaterThan(0);
    expect(waits.mock.calls[0][0].durationMs).toBeLessThanOrEqual(200);
    await pending; expect(execute).toHaveBeenCalledOnce(); expect(next.operator.isAvailable()).toBe(true);
    expect(restored.decomposition.cooldownUntil).toBeUndefined();
  });
});

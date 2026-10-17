import { afterEach, describe, expect, it, vi } from 'vitest';
import { VulnoraCommand } from '../index.js';
import { KillChainPhase, type Mission } from '../types/index.js';
import type { TaskQueue } from '../mission/index.js';

const commands: VulnoraCommand[] = [];
afterEach(() => { vi.restoreAllMocks(); for (const command of commands.splice(0)) { command.stop(); command.opsec.cleanup(); } });
function fixture() {
  const command = new VulnoraCommand({ name: 'Website', llm: { provider: 'mock', model: 'fixture' } });
  commands.push(command);
  command.targetEnv.addTarget({ name: 'Fixture', address: 'https://fixture.test', type: 'web_application', zone: 'external' });
  command.start();
  return command;
}

describe('website mission planning', () => {
  it('retries technical coverage failures and pauses persistently broken work instead of advancing to reporting', async () => {
    const command = fixture(); const mission = command.mission.getActiveMission();
    if (!mission) throw new Error('Missing fixture mission'); command.mission.advancePhase(mission.id);
    vi.spyOn(command.arsenal, 'getReadyToolDefinitions').mockResolvedValue([
      { name: 'nuclei_scan', description: 'Vulnerabilities', parameters: { type: 'object', properties: {} } },
    ]);
    const failure = { id: 'failed', toolName: 'nuclei_scan', toolCategory: 'vulnerability_scan', target: 'https://fixture.test',
      requestParameters: { target: 'https://fixture.test', tags: 'exposure' }, timestamp: Date.now(), status: 'failed',
      executionStatus: 'failed', resultType: 'inconclusive', errorType: 'timeout', result: { success: false, error: 'timeout' } } as unknown as import('../orchestrator/tool-orchestrator.js').EvidenceRecord;
    vi.spyOn(command.arsenal.getOrchestrator(), 'getEvidence').mockReturnValue([failure]);
    const planner = command as unknown as { ensureCoverageBeforeAdvance(mission: Mission, queue: TaskQueue): Promise<boolean>; coverageRecoveryAttempts: Map<string, number> };
    const queue = command.mission.getTaskQueue();
    expect(await planner.ensureCoverageBeforeAdvance(mission, queue)).toBe(true);
    expect(queue.getForMission(mission.id)[0].executionPlan).toMatchObject({ toolName: 'nuclei_scan', repeatReason: 'previous_failure', parameters: failure.requestParameters });
    for (const task of queue.getForMission(mission.id)) queue.fail(task.id, 'timeout');
    planner.coverageRecoveryAttempts.set(`${mission.id}:https://fixture.test:vulnerability_scanning`, 3);
    const blocked = vi.fn(); command.on('recovery:blocked', blocked);
    expect(await planner.ensureCoverageBeforeAdvance(mission, queue)).toBe(true);
    expect(command.isRunning()).toBe(false); expect(mission.currentPhase).toBe(KillChainPhase.WEAPONIZE); expect(blocked).toHaveBeenCalledOnce();
    command.resume(); expect(command.isRunning()).toBe(true);
    expect(await planner.ensureCoverageBeforeAdvance(mission, queue)).toBe(true);
    expect(queue.getPending().some(task => task.executionPlan?.toolName === 'nuclei_scan')).toBe(true);
  });

  it('uses only implemented website phases and does not claim an empty impact validation completed', () => {
    const command = fixture(); const mission = command.mission.getActiveMission();
    expect(mission?.phases).toEqual([KillChainPhase.RECON, KillChainPhase.WEAPONIZE, KillChainPhase.DELIVER, KillChainPhase.ACTIONS]);
    if (!mission) throw new Error('Missing fixture mission');
    const changes: unknown[] = []; command.on('mission:phase_changed', event => changes.push(event));
    command.mission.advancePhase(mission.id); command.mission.advancePhase(mission.id); command.mission.advancePhase(mission.id);
    expect(changes.at(-1)).toMatchObject({ previousPhase: KillChainPhase.DELIVER, previousOutcome: 'not_applicable' });
  });

  it('schedules the missing vulnerability scan even while old reconnaissance gaps remain', async () => {
    const command = fixture(); const mission = command.mission.getActiveMission();
    if (!mission) throw new Error('Missing fixture mission');
    command.mission.advancePhase(mission.id);
    vi.spyOn(command.arsenal, 'getReadyToolDefinitions').mockResolvedValue([
      { name: 'ssl_scan', description: 'TLS', parameters: { type: 'object', properties: {} } },
      { name: 'nuclei_scan', description: 'Vulnerabilities', parameters: { type: 'object', properties: {} } },
    ]);
    const commandPlanner = command as unknown as { ensureCoverageBeforeAdvance(mission: Mission, queue: TaskQueue): Promise<boolean> };
    expect(await commandPlanner.ensureCoverageBeforeAdvance(mission, command.mission.getTaskQueue())).toBe(true);
    expect(command.mission.getTaskQueue().getForMission(mission.id)).toEqual([
      expect.objectContaining({ phase: KillChainPhase.WEAPONIZE, capability: 'vulnerability_scanning', executionPlan: expect.objectContaining({ toolName: 'nuclei_scan' }) }),
    ]);
    expect(command.arsenal.getOrchestrator().getMetrics().incompleteAreas).not.toContain('https://fixture.test: vulnerability_scanning');
  });
});

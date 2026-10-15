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

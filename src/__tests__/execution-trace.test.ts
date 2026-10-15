import { describe, expect, it } from 'vitest';
import { Arsenal, runSubprocess, type ProcessEvent } from '../arsenal/index.js';

describe('actual command execution journal', () => {
  it('captures the exact executable, argv and raw output at the subprocess boundary, without replaying a cached command', async () => {
    const arsenal = new Arsenal();
    const args = ['-e', 'process.stdout.write(JSON.stringify(process.argv.slice(1)))', 'two words', '--actual-argument'];
    arsenal.register({ name: 'fixture_process', category: 'util', description: 'Local fixture', parameters: [],
      handler: async () => {
        const result = await runSubprocess(process.execPath, args);
        return { success: result.exitCode === 0, output: result.stdout };
      } });
    const events: ProcessEvent[] = [];
    arsenal.on('tool:process', event => events.push(event));
    const first = await arsenal.execute('fixture_process', { parameters: {} });
    expect(first.success).toBe(true); expect(first.metadata?.executionTraced).toBe(true);
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({ command: process.execPath, args, type: 'started' });
    expect(events[1]).toMatchObject({ id: events[0].id, type: 'completed', success: true, output: '["two words","--actual-argument"]' });
    await arsenal.execute('fixture_process', { parameters: {} });
    expect(events).toHaveLength(2);
  });
});

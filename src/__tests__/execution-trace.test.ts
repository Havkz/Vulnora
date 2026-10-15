import { describe, expect, it } from 'vitest';
import { Arsenal, runSubprocess, type ProcessEvent } from '../arsenal/index.js';
import { readFile } from 'node:fs/promises';

describe('actual command execution journal', () => {
  it.each(['deadline', 'abort'])('enforces %s even when a tool ignores SIGTERM and holds descendant output pipes', async mode => {
    const child = "process.on('SIGTERM',()=>{}); setTimeout(()=>process.exit(0),8000)";
    const parent = `const {spawn}=require('node:child_process'); const child=spawn(process.execPath,['-e',${JSON.stringify(child)}],{stdio:'inherit'}); console.log('PIDS',process.pid,child.pid); process.on('SIGTERM',()=>{}); setTimeout(()=>process.exit(0),8000)`;
    const started = Date.now();
    const controller = new AbortController();
    const timer = mode === 'abort' ? setTimeout(() => controller.abort(new Error('fixture pause')), 1000) : undefined;
    const result = await runSubprocess(process.execPath, ['-e', parent], { timeout: mode === 'abort' ? 5000 : 1000, signal: controller.signal });
    clearTimeout(timer);
    expect(Date.now() - started).toBeLessThan(3000); expect(result.exitCode).toBe(mode === 'abort' ? -2 : -1);
    const pids = result.stdout.match(/PIDS (\d+) (\d+)/); expect(pids).not.toBeNull();
    for (const pid of pids?.slice(1) || []) {
      await expect.poll(async () => {
        try {
          if (process.platform === 'linux') return (await readFile(`/proc/${pid}/stat`, 'utf8')).split(')')[1].trim().startsWith('Z');
          process.kill(Number(pid), 0); return false;
        } catch (error) { if (['ENOENT', 'ESRCH'].includes(String((error as NodeJS.ErrnoException).code))) return true; throw error; }
      }).toBe(true);
    }
  });
  it('bounds captured output and stops a process that exceeds its output limit', async () => {
    const result = await runSubprocess(process.execPath, ['-e', 'process.stdout.write("x".repeat(10000));setTimeout(()=>{},5000)'], { maxOutput: 100 });
    expect(result.stdout).toHaveLength(100); expect(result.exitCode).toBe(-1);
    expect(result.stderr).toContain('output exceeded capture limit');
  });
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

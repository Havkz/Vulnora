import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProjectStore } from '../projects/store.js';
import { ProjectSession } from '../projects/session.js';
import { runProject } from '../projects/run.js';
import type { EngineCheckpoint } from '../projects/engine-checkpoint.js';
import { resolveInference } from '../cli-inference.js';

const directories: string[] = [];
const sessions: ProjectSession[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0)) await session.close().catch(() => {});
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
  vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.resetModules();
});

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-direct-')); directories.push(directory);
  const store = new ProjectStore(directory);
  const project = await store.create('Direct fixture', 'http://127.0.0.1:1/');
  const configuration = { llm: { provider: 'mock' as const, model: 'fixture' } };
  const session = await ProjectSession.open(store, project.id, configuration); sessions.push(session);
  // Exercise persistence and events without scheduling network work.
  vi.spyOn(session.command as unknown as { tick(): Promise<void> }, 'tick').mockResolvedValue();
  return { store, project, session, configuration, controller: new AbortController() };
}

describe('direct project lifecycle', () => {
  it('cancels, drains and resumes the same persisted project and releases its lease', async () => {
    const { session, store, project, configuration, controller } = await fixture();
    const run = runProject(session, controller.signal, () => {});
    await expect.poll(() => session.command.isRunning()).toBe(true);
    controller.abort(); expect(await run).toBe('interrupted');
    const saved = await store.load(project.id);
    expect(saved.status).toBe('paused');
    expect((saved.checkpoint as EngineCheckpoint).targets[0].address).toBe(project.target.input);
    expect(session.command.isRunning()).toBe(false);
    const restored = await ProjectSession.open(store, project.id, configuration); sessions.push(restored);
    expect(restored.command.targetEnv.getAllTargets()[0].address).toBe(project.target.input);
    expect(restored.command.mission.getAllMissions()).toHaveLength(1);
  });

  it.each(['COMPLETED', 'PARTIALLY_COMPLETED'] as const)('persists a report and distinguishes %s', async status => {
    const { session, store, project, controller } = await fixture();
    const run = runProject(session, controller.signal, () => {});
    await expect.poll(() => session.command.isRunning()).toBe(true);
    const mission = session.command.mission.getActiveMission(); if (!mission) throw new Error('Missing mission');
    session.command.mission.completeMission(mission.id, status);
    session.command.stop();
    expect(await run).toBe(status === 'COMPLETED' ? 'completed' : 'incomplete');
    const saved = await store.load(project.id);
    expect(saved.status).toBe('completed'); expect(saved.report?.markdown).toContain('## Findings');
    expect(await readFile(await store.exportReport(saved), 'utf8')).toBe(saved.report?.markdown);
  });

  it('returns when the engine pauses without a recovery:error event', async () => {
    const { session, controller } = await fixture();
    const run = runProject(session, controller.signal, () => {});
    await expect.poll(() => session.command.isRunning()).toBe(true);
    session.command.pause();
    expect(await run).toBe('paused');
  });

  it('does not start an already cancelled request', async () => {
    const { session, controller } = await fixture();
    const start = vi.spyOn(session, 'start'); controller.abort();
    expect(await runProject(session, controller.signal, () => {})).toBe('interrupted');
    expect(start).not.toHaveBeenCalled();
  });

  it('propagates a journal failure and still releases the project', async () => {
    const { session, store, project, configuration, controller } = await fixture();
    vi.spyOn(store, 'appendLog').mockRejectedValue(new Error('disk full'));
    await expect(runProject(session, controller.signal, () => {})).rejects.toThrow(/disk full|Checkpoint could not be saved/);
    const restored = await ProjectSession.open(store, project.id, configuration); sessions.push(restored);
    expect(restored.command.isRunning()).toBe(false);
  });
});

describe('process-local inference selection', () => {
  it('overrides Codex/Claude models and fallback without modifying saved settings', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-inference-')); directories.push(directory);
    vi.stubEnv('VULNORA_CONFIG_DIR', directory);
    const { config } = await import('../config/index.js');
    config.setDefaultProvider('codex');
    config.setDefaultModel('local', 'installed:7b');
    const before = await readFile(config.getConfigPath(), 'utf8');
    expect(resolveInference(config, { provider: 'codex', model: 'chosen-codex', reasoning: 'high',
      fallbackProvider: 'local', fallbackModel: 'alternate:7b', fallbackOnRefusal: false }))
      .toMatchObject({ provider: 'codex', model: 'chosen-codex', reasoningEffort: 'high',
        fallbackChain: [{ provider: 'local', model: 'alternate:7b' }], fallbackPolicy: { onRefusal: false } });
    expect(resolveInference(config, { provider: 'claude', model: 'sonnet', reasoning: 'medium', fallbackEnabled: false }))
      .toMatchObject({ provider: 'local-agent', model: 'claude', cliModel: 'sonnet', reasoningEffort: 'medium', fallbackChain: [] });
    expect(() => resolveInference(config, { provider: 'local', reasoning: 'high' })).toThrow('Reasoning');
    expect(() => resolveInference(config, { provider: 'claude', reasoning: 'ultra' })).toThrow('Reasoning');
    expect(() => resolveInference(config, { model: '-unsafe' })).toThrow('model');
    expect(() => resolveInference(config, { provider: 'unknown' })).toThrow('provider');
    expect(await readFile(config.getConfigPath(), 'utf8')).toBe(before);
    config.setFallbackSettings({ enabled: false, provider: 'local', model: 'configured-fallback:7b' });
    expect(resolveInference(config, { fallbackEnabled: true }))
      .toMatchObject({ fallbackPolicy: { enabled: true }, fallbackChain: [{ provider: 'local', model: 'configured-fallback:7b' }] });
    expect(config.getFallbackSettings().enabled).toBe(false);
    config.setFallbackSettings({ enabled: true, provider: 'local', model: 'installed:7b' });
    expect(config.getLLMConfig('local').fallbackChain).toEqual([]);
    expect(resolveInference(config, { provider: 'local', model: 'other-primary:7b' }))
      .toMatchObject({ model: 'other-primary:7b', fallbackChain: [{ provider: 'local', model: 'installed:7b' }] });
  });
});

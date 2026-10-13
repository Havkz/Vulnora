import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ProjectStore } from '../projects/store.js';
import { ProjectSession, type ProjectLogEvent } from '../projects/session.js';
import { KillChainPhase, type VulnoraConfig } from '../types/index.js';
import type { EngineCheckpoint } from '../projects/engine-checkpoint.js';

const directories: string[] = [];
const sessions: ProjectSession[] = [];
const configuration: Omit<VulnoraConfig, 'name' | 'hooks'> = { llm: { provider: 'mock', model: 'fixture' } };
afterEach(async () => {
  for (const session of sessions.splice(0)) await session.close();
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function fixture(target = 'https://fixture.test/original/path?mode=read') {
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-session-'));
  directories.push(directory);
  const store = new ProjectStore(directory);
  const project = await store.create('Fixture', target);
  return { store, project };
}

async function open(store: ProjectStore, id: string) {
  const session = await ProjectSession.open(store, id, configuration);
  sessions.push(session);
  return session;
}

describe('persistent project sessions', () => {
  it('blocks model-supplied local and subdomain targets before the tool handler runs, including after resume', async () => {
    const { store, project } = await fixture();
    const first = await open(store, project.id);
    await first.close();
    const session = await open(store, project.id);
    const handler = vi.fn().mockResolvedValue({ success: true, output: 'Selected target' });
    session.command.arsenal.register({ name: 'scope_fixture', category: 'web', description: 'Fixture', parameters: [], handler });
    for (const url of ['http://127.0.0.1:8080', 'http://10.0.0.9', 'https://api.fixture.test']) {
      const result = await session.command.arsenal.execute('scope_fixture', { parameters: { url } });
      expect(result.error).toMatch(/SCOPE DENIED/);
    }
    expect(handler).not.toHaveBeenCalled();
    expect((await session.command.arsenal.execute('scope_fixture', { parameters: { url: project.target.input } })).success).toBe(true);
    expect(handler).toHaveBeenCalledOnce();
  });
  it('opens a READY project with its original target and makes no model or scan request', async () => {
    const target = '  https://fixture.test/path?mode=read  ';
    const { store, project } = await fixture(target);
    const session = await open(store, project.id);
    expect(session.project.target.input).toBe(target);
    expect(session.command.targetEnv.getAllTargets()[0].address).toBe(target.trim());
    expect(session.command.mission.getAllMissions()).toEqual([]);
    expect(session.command.isRunning()).toBe(false);
    expect(session.command.arsenal.getExecutions()).toEqual([]);
    expect(session.project.status).toBe('ready');
    expect((await store.load(project.id)).checkpoint).toBeDefined();
  });

  it('starts only on explicit confirmation and saves repeated close calls consistently', async () => {
    const { store, project } = await fixture();
    const session = await open(store, project.id);
    await session.start();
    expect(session.command.isRunning()).toBe(true);
    expect(session.command.mission.getAllMissions()).toHaveLength(1);
    const first = session.close();
    expect(session.close()).toBe(first);
    await first;
    expect((await store.load(project.id)).status).toBe('paused');
    expect(session.command.arsenal.getExecutions()).toEqual([]);
    await expect(session.start()).rejects.toThrow('closed');
  });

  it('enforces exclusive access and allows reopening after clean shutdown', async () => {
    const { store, project } = await fixture();
    const session = await open(store, project.id);
    await expect(ProjectSession.open(store, project.id, configuration)).rejects.toThrow('exclusive project access');
    await session.close();
    expect((await open(store, project.id)).project.status).toBe('ready');
  });

  it('resumes the existing running scheduler after a drained pause', async () => {
    const { store, project } = await fixture();
    const session = await open(store, project.id);
    const resumed = vi.fn();
    session.command.on('command:resumed', resumed);
    await session.start();
    await session.pause();
    expect(session.project.status).toBe('paused');
    await session.start();
    expect(session.project.status).toBe('running');
    expect(resumed).toHaveBeenCalledOnce();
    expect(session.command.mission.getAllMissions()).toHaveLength(1);
  });

  it('keeps detailed journal content and truthful model fallback events', async () => {
    const { store, project } = await fixture();
    const session = await open(store, project.id);
    const task = { id: 'fixture-task', name: 'Fixture task' } as never;
    const operator = session.command.spawnOperator('Fixture operator', 'recon');
    const content = 'Complete preserved detail with newline.\n'.repeat(400);
    operator.emit('agent:thinking', { task, content });
    session.command.llm.emit('request:fallback', { fromModel: 'codex-default', toModel: 'installed-ollama-model', engaged: true, reason: 'timeout' });
    await session.close();
    const logs = (await new ProjectStore(store.directory).readLogs(project.id)).events as ProjectLogEvent[];
    expect(logs.find(event => event.category === 'scan:progress')?.data).toMatchObject({ detail: content });
    expect(logs.find(event => event.category === 'provider:fallback')?.data).toEqual({ fromModel: 'codex-default', toModel: 'installed-ollama-model', engaged: true, reason: 'timeout' });
  });

  it('persists complete generated results only on request and reopens them without rescanning', async () => {
    const { store, project } = await fixture();
    const session = await open(store, project.id);
    await session.start();
    const mission = session.command.mission.getActiveMission();
    if (!mission) throw new Error('Fixture mission missing');
    session.command.vault.addFinding({ id: 'fixture-finding', title: 'Fixture finding', description: 'Complete fixture explanation.',
      severity: 'medium', targetId: session.command.targetEnv.getAllTargets()[0].id, operatorId: 'fixture-operator', phase: KillChainPhase.RECON,
      discoveredAt: 1, evidence: [{ type: 'response', content: 'Complete fixture response evidence.', timestamp: 1 }], remediation: 'Keep the complete fixture recommendation.' });
    session.command.mission.completeMission(mission.id);
    expect(session.project.report).toBeUndefined();
    const markdown = await session.results();
    expect(markdown).toContain('Complete fixture response evidence.');
    expect(markdown).toContain('Keep the complete fixture recommendation.');
    await session.close();
    const restored = await open(new ProjectStore(store.directory), project.id);
    const generated = vi.spyOn(restored.command, 'generateReport');
    expect(await restored.results()).toBe(markdown);
    expect(generated).not.toHaveBeenCalled();
    await expect(restored.start()).rejects.toThrow('completed');
    expect(restored.command.arsenal.getExecutions()).toEqual([]);
  });

  it('marks an abandoned running project interrupted and keeps its mission instead of reseeding', async () => {
    const { store, project } = await fixture();
    const session = await open(store, project.id);
    await session.start();
    const snapshot = session.command.exportCheckpoint();
    const missionId = snapshot.mission.activeMissionId;
    await session.close();
    const abandoned = await store.load(project.id);
    abandoned.status = 'running'; abandoned.checkpoint = snapshot;
    await store.save(abandoned);
    const recovered = await open(store, project.id);
    expect(recovered.project.status).toBe('interrupted');
    expect(recovered.command.mission.getActiveMission()?.id).toBe(missionId);
    expect(recovered.command.isRunning()).toBe(false);
    await recovered.start();
    expect(recovered.command.mission.getActiveMission()?.id).toBe(missionId);
  });

  it('rejects changed saved targets while preserving the original files and releasing its lease', async () => {
    const { store, project } = await fixture();
    const session = await open(store, project.id);
    await session.close();
    const changed = await store.load(project.id);
    (changed.checkpoint as EngineCheckpoint).targets[0].address = 'https://outside.test';
    await store.save(changed);
    await expect(ProjectSession.open(store, project.id, configuration)).rejects.toThrow('original project target');
    expect((await store.load(project.id)).checkpoint).toEqual(changed.checkpoint);
    (changed.checkpoint as EngineCheckpoint).targets[0].address = changed.target.input.trim();
    await store.save(changed);
    await open(store, project.id);
  });
});

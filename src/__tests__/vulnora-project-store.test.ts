import { describe, it, expect } from 'vitest';
import { mkdtemp, rm, readFile, writeFile, appendFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProjectStore } from '../projects/store.js';
import { validateProjectName, validateProjectTarget } from '../projects/targets.js';

describe('project inputs', () => {
  it.each(['https://example.com/path?x=1', 'http://127.0.0.1:8080/', '127.0.0.1', '::1', '[2001:db8::1]', 'https://[::1]:443/', 'localhost', 'example.com.'])('preserves accepted input %s', value => {
    expect(validateProjectTarget(value).input).toBe(value);
  });
  it.each(['ftp://example.com', 'https://user:secret@example.com', 'https://example.com/#fragment', 'example.com/path', '999.1.1.1', '-host.com', 'host name', '\u001b[31mexample.com', '\nexample.com', '[::1', '::1]', 'https://example.com\\@evil.com', ''])('rejects ambiguous or unsafe target %s', value => {
    expect(() => validateProjectTarget(value)).toThrow();
  });
  it('validates names without turning them into filesystem paths', () => {
    expect(validateProjectName('../../Project')).toBe('../../Project');
    expect(() => validateProjectName('\u001b[31mProject')).toThrow();
    expect(() => validateProjectName(' ')).toThrow();
  });
});

describe('durable project records', () => {
  it('round-trips partial operations, queues, AI context, evidence, full logs and completed reports', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-store-'));
    try {
      const store = new ProjectStore(directory);
      const project = await store.create('Audit', 'https://example.com/path?x=1');
      project.status = 'paused'; project.progress = 31;
      project.checkpoint = { phase: 'recon', queue: ['second'], currentOperation: {
        parameters: { method: 'POST' }, pendingTools: ['second'], completedTools: ['first'], retryAt: 1234,
        messages: [{ role: 'tool', content: 'full intermediate evidence' }],
      }, findings: ['saved finding'] };
      project.report = { markdown: '# All evidence\ntechnical details', generatedAt: Date.now() };
      const detail = 'very detailed event\n'.repeat(1000);
      await Promise.all([store.save(project), store.appendLog(project.id, { detail }), store.appendLog(project.id, { category: 'warning' })]);
      const restarted = new ProjectStore(directory);
      expect(await restarted.load(project.id)).toEqual(project);
      expect((await restarted.readLogs(project.id)).events).toEqual([{ detail }, { category: 'warning' }]);
      project.status = 'completed'; project.progress = 100;
      await store.save(project);
      expect((await restarted.list()).projects[0].status).toBe('completed');
      await expect(store.load('../config')).rejects.toThrow('Invalid project ID');
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
  it('preserves prior checkpoints and reports corrupt metadata or truncated journal tails', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-store-'));
    try {
      const store = new ProjectStore(directory);
      const project = await store.create('Retain', '::1');
      const path = join(directory, `${project.id}.json`);
      const original = await readFile(path, 'utf8');
      await expect(store.save({ ...project, progress: 101 })).rejects.toThrow();
      expect(await readFile(path, 'utf8')).toBe(original);
      await store.appendLog(project.id, { complete: true });
      await appendFile(join(directory, `${project.id}.logs.jsonl`), '{"interrupted":');
      expect(await store.readLogs(project.id)).toEqual({ events: [{ complete: true }], interruptedTail: true });
      const resumed = new ProjectStore(directory);
      await resumed.appendLog(project.id, { resumed: true });
      expect(await resumed.readLogs(project.id)).toEqual({ events: [{ complete: true }, { resumed: true }], interruptedTail: false });
      const backup = (await readdir(directory)).find(file => file.endsWith('.interrupted-log'));
      expect(backup).toBeDefined();
      expect(await readFile(join(directory, backup || ''), 'utf8')).toBe('{"interrupted":');
      await writeFile(path, JSON.stringify({ ...project, version: 99 }));
      const listed = await store.list();
      expect(listed.projects).toHaveLength(0); expect(listed.errors[0]).toContain('Unsupported project version');
      expect(JSON.parse(await readFile(path, 'utf8')).version).toBe(99);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
});

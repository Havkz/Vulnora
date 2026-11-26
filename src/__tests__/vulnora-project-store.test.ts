import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, rm, readFile, writeFile, appendFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProjectStore } from '../projects/store.js';
import { validateProjectName, validateProjectTarget } from '../projects/targets.js';
import { acquireProjectLease } from '../projects/lease.js';

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
  it('redacts older JSON evidence on export and preserves the stored snapshot', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-report-export-'));
    try {
      const store = new ProjectStore(directory);
      const project = await store.create('Archived report', 'https://example.test');
      const snapshot = { schemaVersion: 1, missionId: 'archived', generatedAt: 1,
        summary: { credentialsHarvested: 2 },
        findings: [{ output: 'HTTP/2 200\r\nSet-Cookie: sid=old-value\r\n', metadata: { authorization: 'old-value' } }] };
      project.report = { generatedAt: 1, markdown: '# Archive', json: JSON.stringify(snapshot) };
      await store.save(project);
      const exported = await store.exportReport(await store.load(project.id), 'json');
      expect(JSON.parse(await readFile(exported, 'utf8'))).toEqual({ ...snapshot,
        findings: [{ output: 'HTTP/2 200\r\nSet-Cookie: [redacted]\r\n', metadata: { authorization: '[redacted]' } }] });
      expect((await store.load(project.id)).report).toEqual(project.report);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it('preserves legacy reports and saved data after malformed snapshots or failed exports', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-report-store-'));
    try {
      const store = new ProjectStore(directory);
      const project = await store.create('Report', 'http://127.0.0.1/');
      project.report = { markdown: '# Legacy evidence', generatedAt: 123 };
      await store.save(project);
      const original = await readFile(join(directory, project.id + '.json'), 'utf8');
      await expect(store.exportReport(project, 'json')).rejects.toThrow('legacy report');
      for (const json of ['{', 'null', '{"schemaVersion":99}', '{"schemaVersion":1,"findings":"invalid"}']) {
        await expect(store.save({ ...project, report: { ...project.report, json } })).rejects.toThrow('Invalid saved JSON report');
      }
      const destination = join(directory, 'exports');
      await mkdir(join(destination, project.id + '.report.md'), { recursive: true });
      await expect(store.exportReport(project, 'markdown', destination)).rejects.toThrow();
      expect((await readdir(destination)).filter(name => name.endsWith('.tmp'))).toEqual([]);
      expect(await readFile(join(directory, project.id + '.json'), 'utf8')).toBe(original);
      expect(await readFile(await store.exportReport(project), 'utf8')).toBe(project.report.markdown);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it('renames projects and drafts, protects open projects, and deletes all owned files into recoverable trash', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-manage-'));
    try {
      const store = new ProjectStore(directory);
      const project = await store.create('Before', 'https://fixture.test'); const neighbor = await store.create('Keep', 'https://neighbor.test');
      project.checkpoint = { evidence: 'retain' }; project.report = { markdown: '# Saved report', generatedAt: 1 }; await store.save(project);
      await store.appendLog(project.id, { evidence: 'full log' }); await store.exportReport(project);
      const draft = await store.createDraft('Draft'); await store.renameProject(draft.id, 'Renamed draft');
      expect((await store.listDrafts()).drafts[0].name).toBe('Renamed draft');
      await store.renameProject(project.id, 'After');
      expect(await store.load(project.id)).toMatchObject({ name: 'After', checkpoint: project.checkpoint, report: project.report });
      const release = await acquireProjectLease(directory, project.id);
      try {
        await expect(store.renameProject(project.id, 'Unsafe')).rejects.toThrow('exclusive project');
        await expect(store.deleteProject(project.id)).rejects.toThrow('exclusive project');
      } finally { await release(); }
      await store.deleteProject(project.id); await store.deleteProject(draft.id);
      expect((await store.list()).projects.map(item => item.id)).toEqual([neighbor.id]); expect((await store.listDrafts()).drafts).toEqual([]);
      const archived = (await readdir(join(directory, '.trash'))).find(file => file.startsWith(project.id));
      if (!archived) throw new Error('Missing project archive');
      const trash = join(directory, '.trash', archived);
      expect(JSON.parse(await readFile(join(trash, project.id + '.json'), 'utf8')).name).toBe('After');
      expect(await readFile(join(trash, project.id + '.report.md'), 'utf8')).toBe('# Saved report');
      expect(await readFile(join(trash, project.id + '.logs.jsonl'), 'utf8')).toContain('full log');
      await expect(store.deleteProject('../config')).rejects.toThrow('Invalid project ID');
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

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

import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ProjectStore } from '../projects/store.js';

const directories: string[] = [];
afterEach(async () => { for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true }); });
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-draft-'));
  directories.push(directory);
  return new ProjectStore(directory);
}

describe('persistent project drafts', () => {
  it('retains a name and incomplete target before READY and promotes the same record only after valid input', async () => {
    const store = await fixture();
    const draft = await store.createDraft('Interrupted input', 'stealth');
    draft.targetInput = 'https://';
    await store.saveDraft(draft);
    const restored = new ProjectStore(store.directory);
    expect((await restored.listDrafts()).drafts).toEqual([draft]);
    expect((await restored.list()).projects).toEqual([]);
    await expect(restored.finishDraft(draft)).rejects.toThrow();
    expect((await restored.listDrafts()).drafts).toEqual([draft]);
    draft.targetInput = 'http://[::1]:8080/original';
    const project = await restored.finishDraft(draft);
    expect(project.id).toBe(draft.id);
    expect(project.createdAt).toBe(draft.createdAt);
    expect(project.behavior).toBe('stealth');
    expect(project.target.input).toBe(draft.targetInput);
    expect(project.status).toBe('ready');
    expect((await restored.listDrafts()).drafts).toEqual([]);
  });

  it('ignores a superseded draft left by a crash after READY published', async () => {
    const store = await fixture();
    const draft = await store.createDraft('Boundary');
    draft.targetInput = 'https://fixture.test';
    const project = await store.finishDraft(draft);
    await store.saveDraft(draft);
    expect((await new ProjectStore(store.directory).listDrafts()).drafts).toEqual([]);
    expect((await store.list()).projects).toEqual([project]);
  });

  it('exports the complete saved report atomically without changing its contents', async () => {
    const store = await fixture();
    const project = await store.create('Report', 'https://fixture.test');
    project.status = 'completed';
    project.report = { markdown: '# Complete report\n\nEvidence\n' + 'long multiline detail\n'.repeat(1000), generatedAt: Date.now() };
    await store.save(project);
    const path = await store.exportReport(project);
    expect(await readFile(path, 'utf8')).toBe(project.report.markdown);
    expect((await stat(path)).size).toBe(Buffer.byteLength(project.report.markdown));
  });
});

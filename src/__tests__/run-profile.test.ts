import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadRunProfile, mergeRunOptions } from '../config/run-profile.js';

const directories: string[] = [];
afterEach(async () => { for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true }); });
async function profile(value: unknown) {
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-profile-')); directories.push(directory);
  const path = join(directory, 'run.json');
  await writeFile(path, JSON.stringify(value));
  return { path, directory };
}

describe('run configuration files', () => {
  it('reads validated defaults without modifying the file and resolves output beside it', async () => {
    const { path, directory } = await profile({ version: 1, target: 'https://fixture.test', scope: ['api.fixture.test'],
      exclude: ['admin.fixture.test'], excludeTool: ['nmap_scan'], excludeRisk: ['dangerous'], rateLimit: 2, output: 'reports', reportFormat: 'both',
      provider: 'codex', model: 'chosen-model', reasoning: 'high', fallbackEnabled: true, fallbackOnRefusal: false });
    const before = await readFile(path, 'utf8');
    const loaded = await loadRunProfile(path);
    expect(loaded).toMatchObject({ excludeRisk: ['dangerous'], provider: 'codex', output: join(directory, 'reports'), rateLimit: 2, fallbackOnRefusal: false });
    expect(mergeRunOptions(loaded, { rateLimit: 1, scope: ['other.fixture.test'], fallbackEnabled: false, verbose: undefined }))
      .toMatchObject({ scope: ['other.fixture.test'], exclude: ['admin.fixture.test'], rateLimit: 1, fallbackEnabled: false });
    expect(await readFile(path, 'utf8')).toBe(before);
  });

  it('does not carry a model or reasoning from the file to a different explicit provider', () => {
    expect(mergeRunOptions({ provider: 'local', model: 'fixture:7b', reasoning: 'high', fallbackProvider: 'codex', fallbackModel: 'chosen-codex' },
      { provider: 'claude', fallbackProvider: 'local' }))
      .toEqual({ provider: 'claude', fallbackProvider: 'local' });
    expect(mergeRunOptions({ provider: 'codex', model: 'chosen-codex' }, { provider: 'codex' }).model).toBe('chosen-codex');
  });

  it.each([
    null, [], { version: 2 }, { version: 1, typo: true }, { version: 1, fallbackEnabled: 'false' },
    { version: 1, scope: null }, { version: 1, excludeRisk: ['typo'] }, { version: 1, rateLimit: 0 }, { version: 1, provider: 'mock' },
    { version: 1, reportFormat: 'html' }, { version: 1, target: 'fixture.test' },
    { version: 1, target: 'https://fixture.test', exclude: ['fixture.test'] },
    { version: 1, output: 'bad\u001b[31m' }, { version: 1, apiKey: 'should-never-print' },
  ])('rejects malformed or unsafe configuration %# before a scan starts', async value => {
    const { path } = await profile(value);
    await expect(loadRunProfile(path)).rejects.toThrow();
  });

  it('rejects oversized files and malformed JSON without echoing their contents', async () => {
    const { path } = await profile({ version: 1 });
    await writeFile(path, 'sensitive-invalid-json');
    await expect(loadRunProfile(path)).rejects.toThrow('Invalid JSON in run configuration.');
    await writeFile(path, ' '.repeat(65537));
    await expect(loadRunProfile(path)).rejects.toThrow('64 KiB');
    await writeFile(path, '\uFEFF{"version":1,"provider":"codex"}');
    expect(await loadRunProfile(path)).toEqual({ provider: 'codex' });
    await writeFile(path, Buffer.from([0xff, 0xfe]));
    await expect(loadRunProfile(path)).rejects.toThrow('Invalid JSON');
  });
});

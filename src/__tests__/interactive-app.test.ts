import { afterEach, describe, expect, it, vi } from 'vitest';
import { PassThrough } from 'node:stream';
import type { ReadStream, WriteStream } from 'node:tty';
import { stripVTControlCharacters } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { InteractiveApp, formatProjectLog, type InteractiveServices } from '../ui/app.js';
import { TerminalInterrupted, TerminalSurface } from '../ui/terminal.js';
import * as projectLog from '../ui/project-log.js';
import { visibleWidth } from '../ui/theme.js';
import { ProjectStore } from '../projects/store.js';
import { ProjectSession } from '../projects/session.js';
import { KillChainPhase, type LLMConfig } from '../types/index.js';

const directories: string[] = [];
const surfaces: TerminalSurface[] = [];
const running: Promise<unknown>[] = [];
afterEach(async () => {
  for (const surface of surfaces.splice(0)) { surface.interrupt(); surface.dispose(); }
  await Promise.allSettled(running.splice(0));
  vi.unstubAllEnvs();
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function fixture(llm: LLMConfig = { provider: 'mock', model: 'fixture' }) {
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-ui-'));
  directories.push(directory);
  const input = Object.assign(new PassThrough(), { isTTY: true, isRaw: false, setRawMode(value: boolean) { this.isRaw = value; return this; } });
  const output = Object.assign(new PassThrough(), { isTTY: true, columns: 80, rows: 30 });
  let transcript = '';
  output.on('data', data => { transcript += String(data); });
  const surface = new TerminalSurface(input as unknown as ReadStream, output as unknown as WriteStream);
  surfaces.push(surface);
  const store = new ProjectStore(directory);
  let session: ProjectSession | undefined;
  const open = vi.fn(async (id: string) => { session = await ProjectSession.open(store, id, { llm }); return session; });
  const configuration = { get: () => 'auto', set: vi.fn() } as unknown as InteractiveServices['configuration'];
  const services: InteractiveServices = { configuration, store, open, llm: () => llm,
    installedModels: async () => [], prepareProviders: async () => 'Fixture' };
  const app = new InteractiveApp(surface, services);
  const start = () => { const result = app.run().catch(error => error); running.push(result); return result; };
  const wait = async (text: string) => { await expect.poll(() => stripVTControlCharacters(transcript), { timeout: 5000 }).toContain(text); };
  return { input, output, surface, store, open, services, start, wait, session: () => session, transcript: () => transcript };
}

describe('durable interactive project flow', () => {
  it('pins the current stage, pairs concurrent command results, and separates command blocks', async () => {
    const f = await fixture(); const result = f.start(); const screens = vi.spyOn(f.surface, 'show');
    f.input.write('\rStage fixture\r'); await f.wait('Target URL or IP:');
    f.input.write('https://fixture.test\r'); await f.wait('Press Enter to start'); f.input.write('\r');
    await f.wait('Esc Pause');
    const session = f.session(); if (!session) throw new Error('Missing fixture session');
    const view = () => screens.mock.calls.at(-1)?.[0]() || { lines: [] };
    const text = () => view().lines.map(stripVTControlCharacters).join('\n');
    const stagePosition = view().lines.findIndex(line => line.includes('Stage: Recon'));
    for (const operatorId of ['one', 'two']) session.command.emit('scan:progress', {
      id: 'call-' + operatorId, timestamp: Date.now(), kind: 'tool_call', operatorId, callsign: operatorId, archetype: 'recon', taskId: 'pair-fixture', toolName: 'http_request',
      detail: `http_request {"url":"https://fixture.test/${operatorId}"}`,
    });
    for (const operatorId of ['two', 'one']) session.command.emit('scan:progress', {
      id: 'result-' + operatorId, timestamp: Date.now(), kind: 'tool_result', operatorId, callsign: operatorId, archetype: 'recon', taskId: 'pair-fixture', toolName: 'http_request',
      detail: operatorId + ' OUTPUT', success: operatorId === 'one',
    });
    expect(text().match(/● Ran http_request/g)).toHaveLength(2);
    const content = view().lines.map(stripVTControlCharacters).map(line => line.replace(/^│/, '').replace(/│$/, '').trim()).join('\n');
    expect(content).toMatch(/--url https:\/\/fixture.test\/one\none OUTPUT\n\n● Ran/);
    expect(view().lines.join('\n')).toContain(f.surface.colors.success('●'));
    expect(view().lines.join('\n')).toContain(f.surface.colors.error('●'));
    const mission = session.command.mission.getActiveMission(); if (!mission) throw new Error('Missing mission');
    session.command.mission.advancePhase(mission.id);
    expect(mission.currentPhase).toBe(KillChainPhase.WEAPONIZE);
    expect(view().lines.findIndex(line => line.includes('Stage: Scanning'))).toBe(stagePosition);
    expect(text()).toContain('Recon completed');
    f.input.write('\x18'); expect(await result).toBeInstanceOf(TerminalInterrupted);
    await f.store.flush(session.project.id);
    const journal = await f.store.readLogs(session.project.id);
    expect(journal.events.filter(event => (event as { data?: { taskId?: string } }).data?.taskId === 'pair-fixture')).toHaveLength(4);
  });

  it.each(['running', 'paused'])('saves and exits with Ctrl+X from a %s project', async status => {
    const f = await fixture(); const result = f.start();
    f.input.write('\rExit fixture\r'); await f.wait('Target URL or IP:');
    f.input.write('https://fixture.test\r'); await f.wait('Press Enter to start'); f.input.write('\r');
    await expect.poll(() => f.session()?.command.isRunning()).toBe(true);
    const session = f.session(); if (!session) throw new Error('Missing fixture session');
    if (status === 'paused') { f.input.write('\x1b'); await f.wait('> Resume'); }
    f.input.write('\x18');
    expect(await result).toBeInstanceOf(TerminalInterrupted);
    expect(session.command.isRunning()).toBe(false);
    const saved = await f.store.load(session.project.id);
    expect(saved.status).toBe('paused'); expect(saved.checkpoint).toBeDefined();
    const reopened = await ProjectSession.open(f.store, saved.id, { llm: { provider: 'mock', model: 'fixture' } });
    await reopened.close();
  });

  it('switches to the installed Codex CLI despite an inherited startup provider without a false override notice', async () => {
    const f = await fixture();
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-provider-choice-')); directories.push(directory);
    vi.stubEnv('VULNORA_CONFIG_DIR', directory);
    vi.stubEnv('VULNORA_DEFAULT_PROVIDER', 'codex');
    vi.resetModules();
    const { config } = await import('../config/index.js');
    f.services.configuration = config;
    f.services.installedAgents = async () => ['codex'];
    const prepare = vi.fn(async () => {
      expect(config.getLLMConfig()).toMatchObject({ provider: 'local-agent', model: 'codex' });
      return 'Installed Codex CLI ready';
    });
    f.services.prepareProviders = prepare;
    const result = f.start();
    f.input.write('\x1b[B\x1b[B\r'); await f.wait('Change Default Model / Provider');
    f.input.write('\x1b[B\r'); await f.wait('Installed Codex / Claude CLI');
    f.input.write('\x1b[B\r'); await f.wait('Default model');
    f.input.write('\r'); await f.wait('Installed Codex CLI ready');
    expect(prepare).toHaveBeenCalledTimes(1);
    expect(stripVTControlCharacters(f.transcript())).not.toContain('Environment override');
    expect(process.env.VULNORA_DEFAULT_PROVIDER).toBe('codex');
    f.input.write('\x03'); expect(await result).toBeInstanceOf(TerminalInterrupted);
  });
  it.each([[24, 12], [16, 8]])('keeps READY and completion visible at %s × %s with a long original target and preserves all scrollable metadata', async (columns, rows) => {
    const f = await fixture(); f.output.columns = columns; f.output.rows = rows;
    const target = 'https://fixture.test/' + 'segment/'.repeat(50) + 'TARGET_END';
    const project = await f.store.create('Long project ' + 'x'.repeat(60), target);
    const screens = vi.spyOn(f.surface, 'show'); const result = f.start();
    const view = () => screens.mock.calls.at(-1)?.[0]() || { lines: [] };
    const plain = () => view().lines.map(stripVTControlCharacters).join('\n');
    const content = () => view().lines.map(stripVTControlCharacters).map(line => line.replace(/^│\s*/, '').replace(/\s*│$/, '').trim());
    const bounded = () => {
      expect(view().lines.length).toBeLessThanOrEqual(rows - 2);
      expect(view().lines.every(line => visibleWidth(line) < columns)).toBe(true);
    };
    f.input.write('\x1b[B\r');
    await expect.poll(plain).toContain('Resume Project');
    f.input.write('\x1b[F'); await expect.poll(plain).toContain('Progress: 0%'); bounded();
    f.input.write('\r'); await expect.poll(plain).toContain('READY'); bounded();
    f.input.write('\x1b[F'); await expect.poll(() => content().join('')).toContain('TARGET_END'); bounded();
    expect(content().join(' ')).toContain('Press Enter to start');
    expect(f.open).not.toHaveBeenCalled(); expect((await f.store.load(project.id)).target.input).toBe(target);
    f.input.write('\r'); await expect.poll(() => f.session()?.command.isRunning()).toBe(true);
    const session = f.session(); if (!session) throw new Error('Missing session');
    const report = vi.spyOn(session, 'results');
    const mission = session.command.mission.getActiveMission(); if (!mission) throw new Error('Missing mission');
    session.command.mission.completeMission(mission.id);
    await expect.poll(() => session.project.status).toBe('completed'); f.surface.refresh(); bounded();
    expect(content().join(' ')).toContain('Press Enter to view results');
    expect(report).not.toHaveBeenCalled();
    f.input.write('\r'); await expect.poll(() => report.mock.calls.length).toBe(1);
    f.input.write('\x03'); expect(await result).toBeInstanceOf(TerminalInterrupted);
  });
  it('shows white full output, caches stable logs, and retains the visible content anchor on resize', async () => {
    const f = await fixture(); const result = f.start();
    const screens = vi.spyOn(f.surface, 'show');
    const formatting = vi.spyOn(projectLog, 'formatProjectLog');
    f.input.write('\rLog fixture\r'); await f.wait('Target URL or IP:');
    f.input.write('https://fixture.test\r'); await f.wait('Press Enter to start'); f.input.write('\r');
    await f.wait('Esc Pause');
    const session = f.session(); if (!session) throw new Error('Missing fixture session');
    const detail = 'EVIDENCE_BEGIN\n' + Array.from({ length: 200 }, (_, index) => `Evidence row ${String(index).padStart(3, '0')} · complete technical detail`).join('\n') + '\nEVIDENCE_END';
    session.command.emit('scan:progress', { id: 'colored-fixture', timestamp: Date.now(), kind: 'tool_result',
      operatorId: 'fixture', callsign: 'Fixture', archetype: 'recon', toolName: 'http_request', detail, success: false });
    expect(stripVTControlCharacters(f.transcript())).not.toContain('EVIDENCE_END');
    f.input.write('\x14');
    await f.wait('EVIDENCE_END');
    expect(f.transcript()).toContain(f.surface.colors.bright('EVIDENCE_END'));
    const counted = () => formatting.mock.calls.filter(([event]) => (event.data as { detail?: string })?.detail?.includes('EVIDENCE_BEGIN')).length;
    const before = counted();
    for (let index = 0; index < 20; index++) f.surface.refresh();
    expect(counted()).toBe(before);
    const navigation = vi.spyOn(f.surface, 'nextKey');
    f.input.write('\x1b[H' + '\x1b[B'.repeat(30));
    await expect.poll(() => navigation.mock.calls.length).toBeGreaterThanOrEqual(31);
    const outputStart = f.surface.colors.bright('x').split('x')[0];
    const firstLog = () => stripVTControlCharacters(screens.mock.calls.at(-1)?.[0]().lines.find(line => line.includes(outputStart)) || '')
      .replace(/^│\s*/, '').replace(/\s*│$/, '').trim();
    await expect.poll(firstLog).toContain('Evidence row');
    const anchor = firstLog().slice(0, 20);
    f.output.columns = 40; f.output.emit('resize');
    expect(firstLog()).toContain(anchor); expect(counted()).toBe(before + 1);
    await f.store.flush(session.project.id);
    const journal = await f.store.readLogs(session.project.id);
    expect(journal.events.some(event => (event as { data?: { detail?: string } }).data?.detail === detail)).toBe(true);
    f.input.write('\x14');
    await expect.poll(() => screens.mock.calls.at(-1)?.[0]().footer).toContain('^T Full');
    expect(screens.mock.calls.at(-1)?.[0]().lines.map(stripVTControlCharacters).join('\n')).not.toContain('EVIDENCE_END');
    f.input.write('\x03'); expect(await result).toBeInstanceOf(TerminalInterrupted);
  });
  it('saves the name and incomplete target before READY, preserves edits on Esc, and never starts automatically', async () => {
    const f = await fixture(); const result = f.start();
    const prompts = vi.spyOn(f.surface, 'prompt');
    f.input.write('\rFixture project\r');
    await f.wait('Target URL or IP:');
    expect((await f.store.listDrafts()).drafts[0].name).toBe('Fixture project');
    f.input.write('https://\r');
    await f.wait('Invalid target');
    expect(f.open).not.toHaveBeenCalled();
    f.input.write('\r\x15https://fixture.test:8443/base?mode=read\r');
    await f.wait('Press Enter to start');
    const project = (await f.store.list()).projects[0];
    expect(project.target.input).toBe('https://fixture.test:8443/base?mode=read');
    expect(project.status).toBe('ready');
    expect(f.open).not.toHaveBeenCalled();
    f.input.write('\x1b');
    await expect.poll(() => prompts.mock.calls.length, { timeout: 5000 }).toBe(4);
    f.input.write('/still-editing\x1b');
    await expect.poll(async () => (await f.store.load(project.id)).inputDraft, { timeout: 5000 }).toBe(project.target.input + '/still-editing');
    f.input.write('\x03');
    expect(await result).toBeInstanceOf(TerminalInterrupted);
    expect(f.open).not.toHaveBeenCalled();
  });

  it('starts only on Enter, safely pauses/resumes the real scheduler, and closes on repeated Ctrl+C', async () => {
    const f = await fixture(); const result = f.start();
    f.input.write('\rRuntime fixture\r');
    await f.wait('Target URL or IP:');
    f.input.write('https://fixture.test\r');
    await f.wait('Press Enter to start');
    expect(f.open).not.toHaveBeenCalled();
    f.input.write('\r');
    await expect.poll(() => f.session()?.command.isRunning()).toBe(true);
    const session = f.session();
    expect(session).toBeDefined();
    f.input.write('\x1b');
    await f.wait('> Resume');
    expect(session?.project.status).toBe('paused');
    f.input.write('\r');
    await expect.poll(() => session?.project.status).toBe('running');
    f.input.write('\x03\x03');
    expect(await result).toBeInstanceOf(TerminalInterrupted);
    expect(session?.command.isRunning()).toBe(false);
    const saved = await f.store.load(session?.project.id || '');
    expect(saved.status).toBe('paused');
    expect(saved.checkpoint).toBeDefined();
    const reopened = await ProjectSession.open(f.store, saved.id, { llm: { provider: 'mock', model: 'fixture' } });
    await reopened.close();
  });

  it('persists an unfinished READY edit when interrupted and restores an explicitly empty edit', async () => {
    const f = await fixture(); const project = await f.store.create('Edited project', 'https://fixture.test');
    project.inputDraft = ''; await f.store.save(project);
    const prompts = vi.spyOn(f.surface, 'prompt'); const result = f.start();
    f.input.write('\x1b[B\r'); await f.wait('Resume Project'); f.input.write('\r');
    await f.wait('Press Enter to start'); f.input.write('\x1b');
    await expect.poll(() => prompts.mock.calls.length).toBe(1);
    expect(prompts.mock.calls[0][1]).toBe('');
    f.input.write('https://unfinished'); f.input.write('\x03');
    expect(await result).toBeInstanceOf(TerminalInterrupted);
    const saved = await f.store.load(project.id);
    expect(saved.inputDraft).toBe('https://unfinished');
    expect(saved.target.input).toBe('https://fixture.test'); expect(saved.status).toBe('ready');
    expect(f.open).not.toHaveBeenCalled();
  });

  it('reopens the full saved report and exports it without another scan or provider request', async () => {
    const f = await fixture({ provider: 'deterministic', model: 'evidence-only' });
    const project = await f.store.create('Completed fixture', 'https://fixture.test');
    project.status = 'completed'; project.progress = 100;
    project.report = { markdown: '# Report\n\n' + 'Complete technical evidence\n'.repeat(1000) + 'END OF EVIDENCE', generatedAt: Date.now() };
    await f.store.save(project);
    const result = f.start();
    f.input.write('\x1b[B\r');
    await f.wait('Resume Project');
    f.input.write('\r');
    await f.wait('Saved report:');
    expect(f.session()?.command.isRunning()).toBe(false);
    expect(f.session()?.command.llm.getProvider()).toBe('deterministic');
    expect(f.session()?.command.arsenal.getExecutions()).toEqual([]);
    expect(await readFile(join(f.store.directory, project.id + '.report.md'), 'utf8')).toBe(project.report.markdown);
    f.input.write('\x1b[F');
    await f.wait('END OF EVIDENCE');
    f.input.write('\x03');
    expect(await result).toBeInstanceOf(TerminalInterrupted);
    expect((await f.store.load(project.id)).report).toEqual(project.report);
  });

  it('waits for explicit Enter before generating the report after a real mission completion event', async () => {
    const f = await fixture(); const result = f.start();
    f.input.write('\rCompletion fixture\r');
    await f.wait('Target URL or IP:');
    f.input.write('https://fixture.test\r');
    await f.wait('Press Enter to start'); f.input.write('\r');
    await expect.poll(() => f.session()?.command.isRunning()).toBe(true);
    const session = f.session();
    if (!session) throw new Error('Missing fixture session');
    const report = vi.spyOn(session, 'results');
    const mission = session.command.mission.getActiveMission();
    if (!mission) throw new Error('Missing fixture mission');
    session.command.mission.completeMission(mission.id);
    await f.wait('Press Enter to view results');
    expect(report).not.toHaveBeenCalled();
    f.input.write('\r');
    await f.wait('Saved report:');
    expect(report).toHaveBeenCalledOnce();
    f.input.write('\x03'); expect(await result).toBeInstanceOf(TerminalInterrupted);
    expect((await f.store.load(session.project.id)).report).toBeDefined();
  });

  it('keeps every multiline technical log detail available to the view and journal', () => {
    const detail = 'First evidence line\n' + 'All technical evidence retained\n'.repeat(1000) + 'Final evidence line';
    const formatted = formatProjectLog({ timestamp: 1, category: 'scan:progress', data: { detail } }, true);
    expect(formatted.split('\n').slice(1).map(line => line.replace(/^ {4}/, '')).join('\n')).toBe(detail);
    expect(formatted).toContain('Final evidence line');
  });
});

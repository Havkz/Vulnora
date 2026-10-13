import { afterEach, describe, expect, it, vi } from 'vitest';
import { PassThrough } from 'node:stream';
import type { ReadStream, WriteStream } from 'node:tty';
import { stripVTControlCharacters } from 'node:util';
import { initializeTerminal, TerminalInterrupted, TerminalSurface, terminalText, wrapTerminalText, type InitializationRows, type TerminalFrame } from '../ui/terminal.js';
import { visibleWidth } from '../ui/theme.js';

const surfaces: TerminalSurface[] = [];
afterEach(() => { for (const surface of surfaces.splice(0)) surface.dispose(); vi.useRealTimers(); });

function terminal(columns = 80, rows = 30) {
  const input = Object.assign(new PassThrough(), { isTTY: true, isRaw: false,
    setRawMode(mode: boolean) { this.isRaw = mode; return this; } });
  const output = Object.assign(new PassThrough(), { isTTY: true, columns, rows });
  let transcript = '';
  output.on('data', buffer => { transcript += buffer.toString(); });
  const write = vi.spyOn(output, 'write');
  const surface = new TerminalSurface(input as unknown as ReadStream, output as unknown as WriteStream);
  surfaces.push(surface);
  return { input, output, surface, write, transcript: () => transcript };
}

describe('terminal surface', () => {
  it('handles real arrow and Enter bytes with the requested three-item menu', async () => {
    const { input, surface, transcript } = terminal();
    const selection = surface.menu('VULNORA', ['Create New Project', 'Resume Project', 'Settings']);
    input.write('\x1b[B\x1b[B\x1b[A\r');
    expect(await selection).toBe(1);
    const text = stripVTControlCharacters(transcript());
    expect(text).toContain('> Create New Project');
    expect(text).toContain('> Resume Project');
    expect(text).toContain('> Settings');
    expect(text).not.toContain('Tempest');
    expect(transcript()).not.toContain('\x1b[2J');
  });

  it('keeps entered text editable and returns to the previous screen on Esc', async () => {
    const { input, surface } = terminal();
    const editing = surface.prompt('Project name:', 'ABC');
    input.write('\x1b[D\x7fx\r');
    expect(await editing).toBe('AxC');
    const previous = surface.prompt('Target URL or IP:', 'https://fixture.test/original');
    input.write('\x1b');
    expect(await previous).toBeUndefined();
  });

  it('masks API keys in every repaint', async () => {
    const { input, surface, transcript } = terminal();
    const answer = surface.prompt('API key:', '', true);
    input.write('synthetic-private-key\r');
    expect(await answer).toBe('synthetic-private-key');
    expect(transcript()).not.toContain('synthetic-private-key');
    expect(transcript()).toContain('•');
  });

  it('updates exactly four real initialization rows and reports a failing job honestly', async () => {
    const { surface, transcript } = terminal(80, 12);
    const statuses: InitializationRows[] = [];
    vi.spyOn(surface, 'startup').mockImplementation(rows => {
      statuses.push(structuredClone(rows));
      TerminalSurface.prototype.startup.call(surface, rows);
    });
    const calls: string[] = [];
    const result = await initializeTerminal(surface, [
      async () => { calls.push('configuration'); return 'Configuration read'; },
      async () => { calls.push('scanner'); return 'Tools checked'; },
      async () => { calls.push('LLM'); throw new Error('Ollama unavailable'); },
      async () => { calls.push('projects'); return 'Project files read'; },
    ]);
    expect(calls).toEqual(['configuration', 'scanner', 'LLM', 'projects']);
    expect(statuses.every(rows => rows.length === 4)).toBe(true);
    expect(statuses[0].every(row => row.status === 'pending')).toBe(true);
    expect(result.map(row => row.status)).toEqual(['completed', 'completed', 'failed', 'completed']);
    expect(result[2].detail).toBe('Ollama unavailable');
    expect(transcript()).not.toContain('\x1b[2J');
    expect(stripVTControlCharacters(transcript())).toContain('Starting');
  });

  it('does not mark unfinished initialization successful after cancellation', async () => {
    const { surface } = terminal();
    const controller = new AbortController();
    const next = vi.fn(async () => 'Not run');
    await expect(initializeTerminal(surface, [
      async () => { controller.abort(new Error('save and quit')); throw controller.signal.reason; }, next, next, next,
    ], controller.signal)).rejects.toThrow('save and quit');
    expect(next).not.toHaveBeenCalled();
  });

  it('does not repaint an unchanged frame and fixes the shortcut bar at the bottom', async () => {
    vi.useFakeTimers();
    const { input, surface, output, write } = terminal();
    surface.show(() => ({ lines: ['Stable log'], footer: 'Esc Pause    Ctrl+C Save & Quit' }));
    const before = write.mock.calls.length;
    vi.advanceTimersByTime(500);
    expect(write.mock.calls.length).toBe(before);
    expect(write.mock.calls.some(([value]) => String(value).includes(`\x1b[${output.rows};1H`))).toBe(true);
    const waiting = surface.nextKey();
    const rejected = expect(waiting).rejects.toBeInstanceOf(TerminalInterrupted);
    input.emit('keypress', '\x03', { name: 'c', ctrl: true });
    await rejected;
  });

  it('redraws at the new dimensions and restores keyboard, cursor, and screen once', () => {
    const { input, output, surface, transcript, write } = terminal();
    surface.show(() => ({ lines: wrapTerminalText('Complete text with multiple words.', surface.columns - 1) }));
    output.columns = 20; output.rows = 12; output.emit('resize');
    expect(transcript()).toContain('\x1b[12;1H');
    surface.dispose();
    const calls = write.mock.calls.length;
    surface.dispose();
    expect(write.mock.calls.length).toBe(calls);
    expect(input.isRaw).toBe(false);
    expect(input.isPaused()).toBe(true);
    expect(output.listenerCount('resize')).toBe(0);
    expect(input.listenerCount('keypress')).toBe(0);
    expect(transcript()).toContain('\x1b[?25h\x1b[?1049l');
  });

  it('measures terminal cells and preserves safe multiline Unicode text', () => {
    expect(visibleWidth('航海')).toBe(4);
    expect(visibleWidth('e\u0301')).toBe(1);
    expect(wrapTerminalText('航海 Café\nSecond line', 5).every(line => visibleWidth(line) <= 5)).toBe(true);
    expect(terminalText('\x1b[2JVisible\x1b]0;untrusted title\x07\nkept\r\x08')).toBe('Visible\nkept');
  });

  it('makes all four initialization rows visible at the minimum supported height', () => {
    const { surface } = terminal(40, 8);
    const rows: InitializationRows = ['Configuration', 'Scanner', 'LLM', 'Projects'].map(label => ({ label, status: 'pending' })) as InitializationRows;
    surface.startup(rows);
    const view = (surface as unknown as { screen: () => TerminalFrame }).screen();
    expect(view.lines).toHaveLength(6);
    expect(view.lines.slice(2).map(stripVTControlCharacters)).toEqual(['  · Configuration', '  · Scanner', '  · LLM', '  · Projects']);
  });

  it('rejects the pending screen and emits shutdown when the terminal input closes', async () => {
    const { surface, input } = terminal();
    const interrupted = vi.fn();
    surface.on('interrupt', interrupted);
    const waiting = surface.nextKey();
    const rejected = expect(waiting).rejects.toBeInstanceOf(TerminalInterrupted);
    input.emit('end');
    await rejected;
    expect(interrupted).toHaveBeenCalledTimes(1);
  });

  it.each([[80, 30], [24, 12]])('retains the reference composition at %s columns × %s rows', async (columns, rows) => {
    const { surface, input } = terminal(columns, rows);
    const selection = surface.menu('VULNORA', ['Create New Project', 'Resume Project', 'Settings']);
    const view = (surface as unknown as { screen: () => TerminalFrame }).screen();
    expect(view.lines.map(stripVTControlCharacters).join('\n')).toMatchSnapshot();
    expect(view.lines.every(line => visibleWidth(line) < columns)).toBe(true);
    input.write('\r'); await selection;
  });
});

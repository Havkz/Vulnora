import { EventEmitter } from 'eventemitter3';
import { emitKeypressEvents, type Key } from 'node:readline';
import { stripVTControlCharacters } from 'node:util';
import type { ReadStream, WriteStream } from 'node:tty';
import { createTheme, renderLogo, SPINNER_FRAMES, STATUS_GLYPHS, statusStyle, visibleWidth, type RowStatus } from './theme.js';

export class TerminalInterrupted extends Error {
  constructor() { super('Terminal session interrupted.'); this.name = 'TerminalInterrupted'; }
}

export interface InitializationRow { label: string; status: RowStatus; detail?: string }
export type InitializationRows = [InitializationRow, InitializationRow, InitializationRow, InitializationRow];
export interface TerminalFrame { lines: string[]; footer?: string; cursor?: { row: number; column: number } }

/** Keep control sequences from tool/target text out of the terminal renderer. */
export function terminalText(text: string): string {
  const escape = String.fromCharCode(27);
  const bell = String.fromCharCode(7);
  // Strip complete OSC/DCS strings before Node's CSI stripper can leave their payload behind.
  const withoutStrings = text.replace(new RegExp(`${escape}[\\]PX^_][\\s\\S]*?(?:${bell}|${escape}\\\\|$)`, 'g'), '');
  return [...stripVTControlCharacters(withoutStrings)].filter(char => {
    const code = char.codePointAt(0) || 0;
    return char === '\n' || char === '\t' || (code >= 32 && (code < 127 || code > 159));
  })
    .join('').replace(/\t/g, '    ');
}

export function wrapTerminalText(text: string, columns: number): string[] {
  const width = Math.max(1, columns);
  const result: string[] = [];
  for (const line of terminalText(text).split('\n')) {
    let current = '';
    for (const character of line) {
      if (current && visibleWidth(current + character) > width) { result.push(current); current = ''; }
      current += character;
    }
    result.push(current);
  }
  return result;
}

function fit(text: string, columns: number): string {
  const clean = terminalText(text).replace(/\n/g, ' ');
  if (visibleWidth(clean) <= columns) return clean;
  return wrapTerminalText(clean, Math.max(1, columns - 1))[0] + '…';
}

/** One owner for keyboard input, differential repaint, animation and restoration. */
export class TerminalSurface extends EventEmitter<{ interrupt: void }> {
  readonly colors = createTheme(2);
  private previous: string[] = [];
  private screen?: () => TerminalFrame;
  private timer?: NodeJS.Timeout;
  private frame = 0;
  private keys: { text: string; key: Key }[] = [];
  private waiting?: { resolve: (input: { text: string; key: Key }) => void; reject: (error: Error) => void };
  private stopped = false;
  private disposed = false;
  private previousCursor = '';
  private originalRaw: boolean;
  private originallyPaused: boolean;

  constructor(private input: ReadStream = process.stdin, private output: WriteStream = process.stdout) {
    super();
    if (!input.isTTY || !output.isTTY) throw new Error('Interactive Vulnora requires a terminal. Run vulnora --help for command options.');
    this.originalRaw = input.isRaw;
    this.originallyPaused = input.readableFlowing !== true;
    emitKeypressEvents(input);
    input.setRawMode(true);
    input.on('keypress', this.onKey);
    input.on('end', this.onClosed);
    input.on('error', this.onClosed);
    output.on('resize', this.onResize);
    output.on('error', this.onClosed);
    input.resume();
    output.write('\x1b[?1049h\x1b[?25l');
    this.timer = setInterval(() => { this.frame++; this.paint(); }, 125);
  }

  get columns(): number { return Math.max(1, this.output.columns || 80); }
  get rows(): number { return Math.max(1, this.output.rows || 24); }

  private onKey = (text: string, key: Key): void => {
    if (key.ctrl && key.name === 'c') {
      this.emit('interrupt');
      this.waiting?.reject(new TerminalInterrupted()); this.waiting = undefined;
      this.stopped = true;
      return;
    }
    if (this.waiting) { this.waiting.resolve({ text, key }); this.waiting = undefined; }
    else if (this.keys.length < 8192) this.keys.push({ text, key });
  };

  private onResize = (): void => { this.previous = []; this.paint(); };
  private onClosed = (): void => {
    if (this.disposed || this.stopped) return;
    this.stopped = true;
    this.emit('interrupt');
    this.waiting?.reject(new TerminalInterrupted()); this.waiting = undefined;
  };

  show(screen: () => TerminalFrame): void { this.screen = screen; this.paint(); }

  refresh(): void { this.paint(); }

  interrupt(): void { this.onClosed(); }

  private paint(): void {
    if (!this.screen) return;
    const view = this.screen();
    const lines = this.rows < 8 || this.columns < 16
      ? [this.colors.warning(fit('Resize terminal (minimum 16 columns × 8 rows).', this.columns - 1))]
      : view.lines.slice(0, this.rows - 2);
    while (lines.length < this.rows - 1) lines.push('');
    lines.push(this.colors.muted(fit(view.footer || 'Esc Back    Ctrl+C Save & Quit', this.columns - 1)));
    let update = '';
    for (let index = 0; index < lines.length; index++) {
      if (lines[index] !== this.previous[index]) update += `\x1b[${index + 1};1H\x1b[2K${lines[index]}`;
    }
    this.previous = lines;
    const cursor = view.cursor
      ? `\x1b[?25h\x1b[${Math.max(1, Math.min(this.rows - 1, view.cursor.row + 1))};${Math.min(this.columns, view.cursor.column + 1)}H`
      : '\x1b[?25l';
    if (update || cursor !== this.previousCursor) update += cursor;
    this.previousCursor = cursor;
    if (update) this.output.write(update);
  }

  async nextKey(): Promise<{ text: string; key: Key }> {
    if (this.stopped) throw new TerminalInterrupted();
    const queued = this.keys.shift();
    if (queued) return queued;
    if (this.waiting) throw new Error('Another screen already owns terminal input.');
    return new Promise((resolve, reject) => { this.waiting = { resolve, reject }; });
  }

  logo(): string[] {
    return this.rows >= 24 ? renderLogo(this.columns, this.colors)
      : [this.colors.bright('Vulnora'), this.colors.muted(fit('website & API security testing', this.columns - 1))];
  }

  startup(rows: InitializationRows, footer = 'Ctrl+C Save & Quit'): void {
    this.show(() => ({ lines: [...(this.rows >= 12 ? [...this.logo(), ''] : []), this.colors.accent(`${SPINNER_FRAMES[this.frame % SPINNER_FRAMES.length]} Starting`), '',
      ...rows.map(row => {
        const glyph = row.status === 'active' ? SPINNER_FRAMES[this.frame % SPINNER_FRAMES.length] : STATUS_GLYPHS[row.status];
        const line = fit(`${glyph} ${row.label}${row.detail ? ` · ${row.detail}` : ''}`, this.columns - 4);
        return '  ' + statusStyle(row.status, this.colors)(line);
      })], footer }));
  }

  async menu(title: string, choices: string[], details?: (selected: number) => string[]): Promise<number | undefined> {
    if (!choices.length) throw new Error('Menu must contain at least one choice.');
    let selected = 0;
    this.show(() => {
      const logo = this.rows < 12 ? [] : this.logo();
      const detailLines = details?.(selected).flatMap(line => wrapTerminalText(line, this.columns - 4)) || [];
      const room = Math.max(1, this.rows - logo.length - 5 - detailLines.length);
      const start = Math.max(0, selected - room + 1);
      return { lines: [...logo, ...(logo.length ? [''] : []), this.colors.accent(title), '',
        ...choices.slice(start, start + room).map((label, offset) => {
          const text = fit(label, this.columns - 4);
          return offset + start === selected ? this.colors.accent(`  > ${text}`) : this.colors.foreground(`    ${text}`);
        }), ...detailLines.map(line => '  ' + this.colors.detail(line))], footer: '↑/↓ Select    Enter Confirm    Esc Back    Ctrl+C Save & Quit' };
    });
    for (;;) {
      const { key } = await this.nextKey();
      if (key.name === 'escape') return undefined;
      if (key.name === 'return') return selected;
      if (key.name === 'up') selected = (selected - 1 + choices.length) % choices.length;
      if (key.name === 'down') selected = (selected + 1) % choices.length;
      this.paint();
    }
  }

  async prompt(label: string, initial = '', secret = false, onChange?: (value: string) => void): Promise<string | undefined> {
    let value = [...initial]; let position = value.length;
    this.show(() => {
      const shown = secret ? '•'.repeat(value.length) : value.join('');
      const text = wrapTerminalText(`${label} ${shown}`, this.columns - 4);
      const beforeCursor = `${label} ${secret ? '•'.repeat(position) : value.slice(0, position).join('')}`;
      const cursorLines = wrapTerminalText(beforeCursor, this.columns - 4);
      const logo = this.logo();
      const room = Math.max(1, this.rows - logo.length - 4);
      const first = Math.max(0, cursorLines.length - room);
      return { lines: [...logo, '', ...text.slice(first, first + room).map(line => '  ' + this.colors.foreground(line))],
        cursor: { row: logo.length + cursorLines.length - first, column: 2 + visibleWidth(cursorLines.at(-1) || '') } };
    });
    for (;;) {
      const { text, key } = await this.nextKey();
      if (key.name === 'escape') return undefined;
      if (key.name === 'return') return value.join('');
      if (key.name === 'left') position = Math.max(0, position - 1);
      else if (key.name === 'right') position = Math.min(value.length, position + 1);
      else if (key.name === 'home') position = 0;
      else if (key.name === 'end') position = value.length;
      else if (key.name === 'backspace' && position > 0) value.splice(--position, 1);
      else if (key.name === 'delete') value.splice(position, 1);
      else if (key.ctrl && key.name === 'u') { value = []; position = 0; }
      else if (!key.ctrl && !key.meta && text && terminalText(text) === text && !text.includes('\n') && value.length + [...text].length <= 8192) {
        const characters = [...text]; value.splice(position, 0, ...characters); position += characters.length;
      }
      onChange?.(value.join(''));
      this.paint();
    }
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.timer) { clearInterval(this.timer); this.timer = undefined; }
    this.input.off('keypress', this.onKey); this.output.off('resize', this.onResize);
    this.input.off('end', this.onClosed); this.input.off('error', this.onClosed); this.output.off('error', this.onClosed);
    this.input.setRawMode(this.originalRaw);
    if (this.originallyPaused) this.input.pause();
    this.output.write('\x1b[?25h\x1b[?1049l');
    this.waiting?.reject(new TerminalInterrupted()); this.waiting = undefined;
    this.screen = undefined; this.stopped = true;
  }
}

export async function initializeTerminal(surface: TerminalSurface,
  jobs: [() => Promise<string | void>, () => Promise<string | void>, () => Promise<string | void>, () => Promise<string | void>],
  signal?: AbortSignal): Promise<InitializationRows> {
  const rows: InitializationRows = ['Loading configuration', 'Initializing scanner', 'Connecting to local LLM', 'Loading project environment']
    .map(label => ({ label, status: 'pending' as RowStatus })) as InitializationRows;
  surface.startup(rows);
  for (let index = 0; index < jobs.length; index++) {
    signal?.throwIfAborted();
    rows[index].status = 'active'; surface.startup(rows);
    try { rows[index].detail = await jobs[index]() || undefined; rows[index].status = 'completed'; }
    catch (cause) {
      signal?.throwIfAborted();
      rows[index].detail = cause instanceof Error ? cause.message : String(cause); rows[index].status = 'failed';
    }
    surface.startup(rows);
  }
  return rows;
}

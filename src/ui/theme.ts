import chalk, { Chalk } from 'chalk';
import { stripVTControlCharacters } from 'node:util';

// VoidAccess main.py/display.py: preserve indexed colors and standard ANSI status colors.
export const THEME_TOKENS = Object.freeze({
  accent: 141, secondary: 183, border: 5, foreground: 7, bright: 15,
  muted: 244, detail: 247, active: 6, success: 2, error: 1, warning: 3,
});

export const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'] as const;
export type RowStatus = 'pending' | 'active' | 'completed' | 'failed' | 'skipped';
export const STATUS_GLYPHS: Record<RowStatus, string> = {
  pending: '·', active: '⠹', completed: '✓', failed: '✗', skipped: '↷',
};

export function createTheme(level = chalk.level) {
  const colors = new Chalk({ level });
  return {
    accent: colors.ansi256(THEME_TOKENS.accent),
    secondary: colors.ansi256(THEME_TOKENS.secondary),
    border: colors.ansi256(THEME_TOKENS.border),
    foreground: colors.ansi256(THEME_TOKENS.foreground),
    bright: colors.ansi256(THEME_TOKENS.bright),
    muted: colors.ansi256(THEME_TOKENS.muted),
    detail: colors.ansi256(THEME_TOKENS.detail),
    active: colors.ansi256(THEME_TOKENS.active),
    success: colors.ansi256(THEME_TOKENS.success),
    error: colors.ansi256(THEME_TOKENS.error),
    warning: colors.ansi256(THEME_TOKENS.warning),
    emphasis: colors.bold,
  };
}

export const theme = createTheme();
export type TerminalTheme = ReturnType<typeof createTheme>;

export function visibleWidth(text: string): number {
  return [...stripVTControlCharacters(text)].length;
}

export function centerLines(lines: string[], width: number): string[] {
  const widest = Math.max(0, ...lines.map(visibleWidth));
  const axis = Math.floor(Math.max(0, width - widest) / 2) + widest / 2;
  return lines.map(line => ' '.repeat(Math.max(0, Math.round(axis - visibleWidth(line) / 2))) + line);
}

export function renderLogo(width: number, colors: TerminalTheme = theme): string[] {
  const primary = colors.accent;
  const shade = colors.secondary;
  if (width < 25) return centerLines([colors.bright('Vulnora')], width);
  const disk = [
    shade('     ░░░░░') + primary('█') + shade('░░░░░'),
    shade('  ░░') + primary('█'.repeat(17)) + shade('░░'),
    shade(' ░') + primary('█'.repeat(21)) + shade('░'),
    shade('░') + primary('█'.repeat(23)) + shade('░'),
    shade('░') + primary('█'.repeat(23)) + shade('░'),
    primary('███████') + '  ' + colors.bright('Vulnora') + '  ' + primary('███████'),
    shade('░') + primary('█'.repeat(23)) + shade('░'),
    shade('░') + primary('█'.repeat(23)) + shade('░'),
    shade(' ░') + primary('█'.repeat(21)) + shade('░'),
    shade('  ░░') + primary('█'.repeat(17)) + shade('░░'),
    shade('     ░░░░░') + primary('█') + shade('░░░░░'),
  ];
  const caption = width >= 30 ? ['website & API security testing'] : ['website & API', 'security testing'];
  return centerLines([...disk, ...caption.map(line => colors.muted(line))], width);
}

export function statusStyle(status: RowStatus, colors: TerminalTheme = theme) {
  return { pending: colors.muted, active: colors.active, completed: colors.success,
    failed: colors.error, skipped: colors.warning }[status];
}

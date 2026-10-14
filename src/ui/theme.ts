import chalk, { Chalk } from 'chalk';
import stringWidth from 'string-width';

// Vulnora's steel-blue identity; standard status colors retain their meaning.
export const THEME_TOKENS = Object.freeze({
  accent: 75, secondary: 109, border: 67, foreground: 7, bright: 15,
  muted: 244, detail: 247, active: 80, success: 2, error: 1, warning: 3,
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

export function severityStyle(severity: string, colors: TerminalTheme = theme) {
  switch (severity.toLowerCase()) {
    case 'critical': case 'high': case 'severe': return colors.error;
    case 'medium': return colors.warning;
    case 'low': return colors.success;
    case 'info': return colors.muted;
    default: return colors.foreground;
  }
}

export function visibleWidth(text: string): number {
  return stringWidth(text);
}

export function centerLines(lines: string[], width: number): string[] {
  const widest = Math.max(0, ...lines.map(visibleWidth));
  const axis = Math.floor(Math.max(0, width - widest) / 2) + widest / 2;
  return lines.map(line => ' '.repeat(Math.max(0, Math.round(axis - visibleWidth(line) / 2))) + line);
}

export function renderLogo(width: number, colors: TerminalTheme = theme): string[] {
  const primary = colors.accent;
  if (width < 26) return centerLines([colors.bright('Vulnora')], width);
  const browser = [
    '╭───────────────────────╮',
    '│ · · ·       https://  │',
    '├───────────────────────┤',
    '│          ╭───╮        │',
    '│          │   │        │',
    '│        ╭─┴───┴─╮      │',
    '│        │   ●   │      │',
    '│        │   │   │      │',
    '│        ╰───────╯      │',
    '╰───────────────────────╯',
  ].map(line => primary(line));
  const caption = ['website pentesting tool'];
  return centerLines([...browser, colors.emphasis(colors.bright('V U L N O R A')),
    ...caption.map(line => colors.muted(line))], width);
}

export function statusStyle(status: RowStatus, colors: TerminalTheme = theme) {
  return { pending: colors.muted, active: colors.active, completed: colors.success,
    failed: colors.error, skipped: colors.warning }[status];
}

import { theme, severityStyle, type TerminalTheme } from './ui/theme.js';

function colorSeverity(value: string, colors: TerminalTheme): string {
  const normalized = value.trim().replace(/\*/g, '');
  return severityStyle(normalized, colors)(normalized.toUpperCase());
}

function formatInlineMarkdown(value: string, colors: TerminalTheme): string {
  return value
    .replace(/`([^`]+)`/g, (_match, content: string) => colors.active(content))
    .replace(/\*{3}([^*]+)\*{3}/g, (_match, content: string) => colors.emphasis.italic(content))
    .replace(/\*{2}([^*]+)\*{2}/g, (_match, content: string) => colors.emphasis(content))
    .replace(/\*([^*]+)\*/g, (_match, content: string) => colors.emphasis.italic(content));
}

function formatTableRow(line: string, colors: TerminalTheme): string {
  if (/^\|[-:|\s]+\|$/.test(line)) return colors.muted(line);
  const cells = line.slice(1, -1).split('|').map(cell => cell.trim());
  const rendered = cells.map((cell, index) => {
    if (index === 0 && /^(critical|high|severe|medium|low|info)$/i.test(cell)) {
      return colorSeverity(cell, colors);
    }
    return formatInlineMarkdown(cell, colors);
  });
  return `${colors.muted('|')} ${rendered.join(` ${colors.muted('|')} `)} ${colors.muted('|')}`;
}

/** Add terminal-only severity colors without putting ANSI escapes into Markdown/API reports. */
export function formatTerminalReport(markdown: string, colors: TerminalTheme = theme): string {
  let fence: { character: string; length: number } | undefined;
  return markdown.split('\n').map(line => {
    const marker = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if (fence) {
      if (marker && marker[1][0] === fence.character && marker[1].length >= fence.length && !marker[2].trim()) {
        fence = undefined; return '';
      }
      return colors.foreground(line);
    }
    if (marker) { fence = { character: marker[1][0], length: marker[1].length }; return ''; }
    const findingSeverity = line.match(/^\s*\*{0,3}Severity:\*{0,3}\s*\*{0,3}([A-Za-z_-]+)\*{0,3}\s*$/i);
    if (findingSeverity) return `${colors.emphasis('Severity:')} ${colorSeverity(findingSeverity[1], colors)}`;

    const riskRating = line.match(/^(\s*-\s*)\*{0,3}Overall Risk Rating:\*{0,3}\s*\*{0,3}([A-Za-z_-]+)\*{0,3}\s*$/i);
    if (riskRating) return `${colors.active(riskRating[1])}${colors.emphasis('Overall Risk Rating:')} ${colorSeverity(riskRating[2], colors)}`;

    const impactLevel = line.match(/^\s*\*{0,3}Impact Level:\*{0,3}\s*\*{0,3}([A-Za-z_-]+)\*{0,3}\s*$/i);
    if (impactLevel) return `${colors.emphasis('Impact Level:')} ${colorSeverity(impactLevel[1], colors)}`;

    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      const title = formatInlineMarkdown(heading[2], colors);
      return heading[1].length === 2 ? colors.secondary.bold(title) : colors.accent.bold(title);
    }

    if (line.startsWith('|') && line.endsWith('|')) return formatTableRow(line, colors);

    if (/^\s*-\s+/.test(line)) {
      const bulletLine = line.replace(/^(\s*)-\s+/, (_match, indent: string) => `${indent}${colors.active('•')} `);
      return formatInlineMarkdown(bulletLine, colors);
    }

    return formatInlineMarkdown(line, colors);
  }).join('\n');
}

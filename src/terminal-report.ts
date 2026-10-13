import { theme } from './ui/theme.js';

function colorSeverity(value: string): string {
  const normalized = value.trim().replace(/\*/g, '');
  switch (normalized.toLowerCase()) {
    case 'info':
      return theme.muted(normalized.toUpperCase());
    case 'low':
      return theme.success(normalized.toUpperCase());
    case 'medium':
      return theme.warning(normalized.toUpperCase());
    case 'high':
    case 'severe':
    case 'critical':
      return theme.error(normalized.toUpperCase());
    default:
      return normalized.toUpperCase();
  }
}

function formatInlineMarkdown(value: string): string {
  return value
    .replace(/`([^`]+)`/g, (_match, content: string) => theme.active(content))
    .replace(/\*{3}([^*]+)\*{3}/g, (_match, content: string) => theme.emphasis.italic(content))
    .replace(/\*{2}([^*]+)\*{2}/g, (_match, content: string) => theme.emphasis(content))
    .replace(/\*([^*]+)\*/g, (_match, content: string) => theme.emphasis.italic(content));
}

function formatTableRow(line: string): string {
  if (/^\|[-:|\s]+\|$/.test(line)) return theme.muted(line);
  const cells = line.slice(1, -1).split('|').map(cell => cell.trim());
  const rendered = cells.map((cell, index) => {
    if (index === 0 && /^(critical|high|severe|medium|low|info)$/i.test(cell)) {
      return colorSeverity(cell);
    }
    return formatInlineMarkdown(cell);
  });
  return `${theme.muted('|')} ${rendered.join(` ${theme.muted('|')} `)} ${theme.muted('|')}`;
}

/** Add terminal-only severity colors without putting ANSI escapes into Markdown/API reports. */
export function formatTerminalReport(markdown: string): string {
  return markdown.split('\n').map(line => {
    const findingSeverity = line.match(/^\s*\*{0,3}Severity:\*{0,3}\s*\*{0,3}([A-Za-z_-]+)\*{0,3}\s*$/i);
    if (findingSeverity) return `${theme.emphasis('Severity:')} ${colorSeverity(findingSeverity[1])}`;

    const riskRating = line.match(/^(\s*-\s*)\*{0,3}Overall Risk Rating:\*{0,3}\s*\*{0,3}([A-Za-z_-]+)\*{0,3}\s*$/i);
    if (riskRating) return `${theme.active(riskRating[1])}${theme.emphasis('Overall Risk Rating:')} ${colorSeverity(riskRating[2])}`;

    const impactLevel = line.match(/^\s*\*{0,3}Impact Level:\*{0,3}\s*\*{0,3}([A-Za-z_-]+)\*{0,3}\s*$/i);
    if (impactLevel) return `${theme.emphasis('Impact Level:')} ${colorSeverity(impactLevel[1])}`;

    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      const title = formatInlineMarkdown(heading[2]);
      if (heading[1].length === 1) return theme.active.bold(title);
      if (heading[1].length === 2) return theme.warning.bold(title);
      return theme.active.bold(title);
    }

    if (line.startsWith('|') && line.endsWith('|')) return formatTableRow(line);

    if (/^\s*-\s+/.test(line)) {
      const bulletLine = line.replace(/^(\s*)-\s+/, (_match, indent: string) => `${indent}${theme.active('•')} `);
      return formatInlineMarkdown(bulletLine);
    }

    return formatInlineMarkdown(line);
  }).join('\n');
}

import chalk from 'chalk';

function colorSeverity(value: string): string {
  const normalized = value.trim().replace(/\*/g, '');
  switch (normalized.toLowerCase()) {
    case 'info':
      return chalk.gray(normalized.toUpperCase());
    case 'low':
      return chalk.green(normalized.toUpperCase());
    case 'medium':
      return chalk.yellow(normalized.toUpperCase());
    case 'high':
    case 'severe':
    case 'critical':
      return chalk.red(normalized.toUpperCase());
    default:
      return normalized.toUpperCase();
  }
}

function formatInlineMarkdown(value: string): string {
  return value
    .replace(/`([^`]+)`/g, (_match, content: string) => chalk.cyan(content))
    .replace(/\*{3}([^*]+)\*{3}/g, (_match, content: string) => chalk.bold.italic(content))
    .replace(/\*{2}([^*]+)\*{2}/g, (_match, content: string) => chalk.bold(content))
    .replace(/\*([^*]+)\*/g, (_match, content: string) => chalk.italic(content));
}

function formatTableRow(line: string): string {
  if (/^\|[-:|\s]+\|$/.test(line)) return chalk.gray(line);
  const cells = line.slice(1, -1).split('|').map(cell => cell.trim());
  const rendered = cells.map((cell, index) => {
    if (index === 0 && /^(critical|high|severe|medium|low|info)$/i.test(cell)) {
      return colorSeverity(cell);
    }
    return formatInlineMarkdown(cell);
  });
  return `${chalk.gray('|')} ${rendered.join(` ${chalk.gray('|')} `)} ${chalk.gray('|')}`;
}

/** Add terminal-only severity colors without putting ANSI escapes into Markdown/API reports. */
export function formatTerminalReport(markdown: string): string {
  return markdown.split('\n').map(line => {
    const findingSeverity = line.match(/^\s*\*{0,3}Severity:\*{0,3}\s*\*{0,3}([A-Za-z_-]+)\*{0,3}\s*$/i);
    if (findingSeverity) return `${chalk.bold('Severity:')} ${colorSeverity(findingSeverity[1])}`;

    const riskRating = line.match(/^(\s*-\s*)\*{0,3}Overall Risk Rating:\*{0,3}\s*\*{0,3}([A-Za-z_-]+)\*{0,3}\s*$/i);
    if (riskRating) return `${chalk.cyan(riskRating[1])}${chalk.bold('Overall Risk Rating:')} ${colorSeverity(riskRating[2])}`;

    const impactLevel = line.match(/^\s*\*{0,3}Impact Level:\*{0,3}\s*\*{0,3}([A-Za-z_-]+)\*{0,3}\s*$/i);
    if (impactLevel) return `${chalk.bold('Impact Level:')} ${colorSeverity(impactLevel[1])}`;

    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      const title = formatInlineMarkdown(heading[2]);
      if (heading[1].length === 1) return chalk.bold.cyan(title);
      if (heading[1].length === 2) return chalk.bold.yellow(title);
      return chalk.bold.blue(title);
    }

    if (line.startsWith('|') && line.endsWith('|')) return formatTableRow(line);

    if (/^\s*-\s+/.test(line)) {
      const bulletLine = line.replace(/^(\s*)-\s+/, (_match, indent: string) => `${indent}${chalk.cyan('•')} `);
      return formatInlineMarkdown(bulletLine);
    }

    return formatInlineMarkdown(line);
  }).join('\n');
}

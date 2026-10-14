import { stripVTControlCharacters as stripAnsi } from 'node:util';
import { describe, expect, it } from 'vitest';
import { formatTerminalReport } from '../terminal-report.js';
import { createTheme } from '../ui/theme.js';


describe('terminal report formatting', () => {
  it('uses the shared palette and preserves literal technical content inside fenced evidence', () => {
    const colors = createTheme(2);
    const literal = '**literal evidence** | columns | `exact bytes`\n```short fence\nEND OF EVIDENCE';
    const rendered = formatTerminalReport(`# Findings\n\n\`\`\`\`text\n${literal}\n\`\`\`\`\n**Severity:** CRITICAL`, colors);
    expect(rendered).toContain(colors.accent.bold('Findings'));
    expect(rendered).toContain(colors.error('CRITICAL'));
    expect(stripAnsi(rendered)).toContain(literal);
  });
  it('removes markdown decoration while preserving readable report content', () => {
    const rendered = stripAnsi(formatTerminalReport([
      '# Security Assessment Report',
      '**Generated:** now',
      '| Severity | Count |',
      '|----------|-------|',
      '| Critical | 1 |',
      '**Severity:** CRITICAL',
      '- **Overall Risk Rating:** SEVERE',
      '**Evidence:** `verified output`',
    ].join('\n')));

    expect(rendered).toContain('Security Assessment Report');
    expect(rendered).toContain('Severity: CRITICAL');
    expect(rendered).toContain('Overall Risk Rating: SEVERE');
    expect(rendered).toContain('Evidence: verified output');
    expect(rendered).not.toMatch(/\*\*|```?/);
  });
});

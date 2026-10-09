import { stripVTControlCharacters as stripAnsi } from 'node:util';
import { describe, expect, it } from 'vitest';
import { formatTerminalReport } from '../terminal-report.js';


describe('terminal report formatting', () => {
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

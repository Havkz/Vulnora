import { describe, expect, it } from 'vitest';
import { stripVTControlCharacters } from 'node:util';
import { formatProjectLog, projectActivity } from '../ui/project-log.js';
import { createTheme } from '../ui/theme.js';
import type { ProjectLogEvent } from '../projects/session.js';

describe('readable project logs', () => {
  it('renders recorded tool arguments with distinct colors and without internal JSON metadata', () => {
    const colors = createTheme(2);
    const event: ProjectLogEvent = { timestamp: 1, category: 'scan:progress', data: {
      id: 'internal-id', kind: 'tool_call', callsign: 'Recon-1', toolName: 'http_request',
      detail: 'http_request {"url":"https://fixture.test/robots.txt","method":"GET"}',
    } };
    const text = formatProjectLog(event, false, colors);
    expect(text).toContain(colors.accent('http_request'));
    expect(text).toContain(colors.secondary('--url'));
    expect(text).toContain(colors.detail('https://fixture.test/robots.txt'));
    expect(stripVTControlCharacters(text)).toContain('Ran · Recon-1');
    expect(text).not.toContain('internal-id'); expect(text).not.toContain('"kind"');
    expect(projectActivity(event)).toBe('Working · http_request');
  });

  it('previews three output lines and retains the entire command output in transcript mode', () => {
    const detail = 'First\nSecond\nThird\nFourth\nFifth';
    const event = { timestamp: 1, category: 'scan:progress', data: { kind: 'tool_result', toolName: 'nmap_scan', detail, success: true } };
    const brief = formatProjectLog(event);
    expect(brief).toContain('Third'); expect(brief).not.toContain('Fourth');
    expect(brief).toContain('+ 2 lines (Ctrl+T full output)');
    const full = formatProjectLog(event, true);
    expect(full.split('\n').slice(1).map(line => line.replace(/^ {2}└ /, '')).join('\n')).toBe(detail);
    expect(full).not.toContain('Ctrl+T');
  });

  it('shows actual provider thinking without flooding the brief view with protocol events or model JSON', () => {
    const event = (type: string) => ({ timestamp: 1, category: 'provider:progress', data: { agent: 'codex', type, text: '{"tool_calls":[]}' } });
    expect(formatProjectLog(event('thread.started'))).toBe('');
    expect(formatProjectLog(event('turn.started'))).toContain('Thinking · codex');
    expect(projectActivity(event('turn.started'))).toBe('Thinking · codex');
    expect(formatProjectLog(event('item.completed'))).not.toContain('tool_calls');
    expect(formatProjectLog(event('item.completed'), true)).toContain('tool_calls');
  });

  it('bounds previews of long output lines and distinguishes an intentional pause from a task error', () => {
    const detail = 'word '.repeat(80);
    const long = { timestamp: 1, category: 'scan:progress', data: { kind: 'tool_result', detail } };
    expect(formatProjectLog(long, false, undefined, 24).split('\n')).toHaveLength(5);
    expect(formatProjectLog(long, true)).toContain(detail);
    const paused = { timestamp: 1, category: 'scan:progress', data: { kind: 'task_failed', taskName: 'Content Discovery', success: false, detail: 'aborted: project pause' } };
    expect(formatProjectLog(paused)).toContain('Paused · Content Discovery');
  });

  it('strips untrusted terminal control sequences and credentials from tool output', () => {
    const event = { timestamp: 1, category: 'scan:progress', data: { kind: 'tool_result', success: false,
      detail: '\u001b[2JVisible\u001b]0;title\u0007\ntoken=secret-fixture-value-1234567890' } };
    const text = formatProjectLog(event, true);
    expect(text).toContain('Visible'); expect(text).not.toContain('title');
    expect(text).not.toContain('\u001b'); expect(text).not.toContain('secret-fixture-value');
  });
});

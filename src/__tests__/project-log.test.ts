import { describe, expect, it } from 'vitest';
import { stripVTControlCharacters } from 'node:util';
import { formatProjectLog, formatSavedProjectLog, projectActivity } from '../ui/project-log.js';
import { createTheme } from '../ui/theme.js';
import type { ProjectLogEvent } from '../projects/session.js';

describe('readable project logs', () => {
  it('keeps complete protocol events and technical metadata accessible in saved logs', () => {
    const event = { timestamp: 1, category: 'provider:progress', data: { type: 'item.completed', text: '{"tool_calls":[]}', operatorId: 'fixture-operator' } };
    expect(formatProjectLog(event)).toBe('');
    expect(formatSavedProjectLog(event)).toContain('item.completed');
    expect(formatSavedProjectLog(event)).toContain('fixture-operator');
    const detail = 'Complete observation\n'.repeat(200);
    expect(formatSavedProjectLog({ timestamp: 1, category: 'scan:progress', data: { detail, taskName: 'Recorded task' } })).toContain(detail);
  });
  it('renders recorded tool arguments with distinct colors and without internal JSON metadata', () => {
    const colors = createTheme(2);
    const event: ProjectLogEvent = { timestamp: 1, category: 'scan:progress', data: {
      id: 'internal-id', kind: 'tool_call', callsign: 'Recon-1', toolName: 'http_request',
      detail: 'http_request {"url":"https://fixture.test/robots.txt","method":"GET"}',
    } };
    const text = formatProjectLog(event, false, colors);
    expect(text).toContain(colors.command('http_request'));
    expect(text).toContain(colors.error('--url'));
    expect(text).toContain(colors.muted('https://fixture.test/robots.txt'));
    expect(stripVTControlCharacters(text)).toContain('● Ran http_request --url');
    expect(text.endsWith('\n')).toBe(true);
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
    expect(full.split('\n').slice(1, -1).map(line => line.replace(/^ {4}/, '')).join('\n')).toBe(detail);
    expect(full).not.toContain('Ctrl+T');
  });

  it('shows actual provider thinking without flooding the brief view with protocol events or model JSON', () => {
    const event = (type: string) => ({ timestamp: 1, category: 'provider:progress', data: { agent: 'codex', type, text: '{"tool_calls":[]}' } });
    expect(formatProjectLog(event('thread.started'))).toBe('');
    expect(formatProjectLog(event('turn.started'))).toBe('');
    expect(projectActivity(event('turn.started'))).toBe('Thinking · codex');
    expect(formatProjectLog(event('item.completed'))).not.toContain('tool_calls');
    expect(formatProjectLog(event('item.completed'), true)).toBe('');
    expect(formatProjectLog({ timestamp: 1, category: 'scan:progress', data: { kind: 'thinking', detail: '```json\n{"tool_calls":[]}\n```' } })).toBe('');
  });

  it('bounds previews of long output lines and distinguishes an intentional pause from a task error', () => {
    const detail = 'word '.repeat(80);
    const long = { timestamp: 1, category: 'scan:progress', data: { kind: 'tool_result', detail } };
    expect(formatProjectLog(long, false, undefined, 24).split('\n')).toHaveLength(6);
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

  it('colors only flags and quoted strings, and uses result-colored dots with gray or white output', () => {
    const colors = createTheme(2);
    const call = { timestamp: 1, category: 'scan:progress', data: { kind: 'tool_call', toolName: 'curl', detail: 'curl -u user --retry=2 -H "Accept: application/json" \'https://fixture.test\'' } };
    const result = (success: boolean) => ({ timestamp: 2, category: 'scan:progress', data: { kind: 'tool_result', success, detail: 'First\nSecond' } });
    const brief = formatProjectLog(call, false, colors, 80, result(true));
    expect(brief).toContain(colors.success('●') + ' ' + colors.foreground('Ran') + ' ' + colors.command('curl'));
    expect(brief).toContain(colors.error('-u')); expect(brief).toContain(colors.muted('user'));
    expect(brief).toContain(colors.error('--retry') + colors.muted('=2'));
    expect(brief).toContain(colors.success('"Accept: application/json"'));
    expect(brief).toContain(colors.success("'https://fixture.test'"));
    expect(brief).toContain('    ' + colors.muted('First'));
    const full = formatProjectLog(call, true, colors, 80, result(false));
    expect(full).toContain(colors.error('●'));
    expect(full).toContain('    ' + colors.bright('First'));
    expect(full).not.toContain(colors.error('First'));
  });

  it('names completed and newly active scan stages explicitly', () => {
    const text = formatProjectLog({ timestamp: 1, category: 'mission:phase_changed', data: { previousPhase: 'reconnaissance', phase: 'weaponization' } });
    expect(text).toBe('Recon completed\n\nStage: Scanning');
    expect(formatProjectLog({ timestamp: 1, category: 'project:completed', data: { phase: 'actions_on_objectives' } })).toContain('Reporting completed');
    expect(formatProjectLog({ timestamp: 1, category: 'project:completed', data: {} })).toBe('Scan completed');
  });
});

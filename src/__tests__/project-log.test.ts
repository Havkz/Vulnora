import { describe, expect, it } from 'vitest';
import { stripVTControlCharacters } from 'node:util';
import { formatAIHistory, formatDuration, formatProjectLog, formatSavedProjectLog, phasePath, ProjectActivity } from '../ui/project-log.js';
import { createTheme } from '../ui/theme.js';
import type { ProjectLogEvent } from '../projects/session.js';

describe('readable project logs', () => {
  it('shows a colored website phase path with the active stage identified without percentages', () => {
    const colors = createTheme(2);
    const path = phasePath('weaponization', colors);
    expect(stripVTControlCharacters(path)).toBe('Recon -> [Scanning] -> Impact validation -> Reporting');
    expect(path).toContain(colors.command('Recon')); expect(path).toContain(colors.active('[Scanning]'));
    expect(path).toContain(colors.warning('Impact validation')); expect(path).not.toContain('%');
  });
  it('aligns scanner padding, wrapped output and the expansion hint at four spaces', () => {
    const result = { timestamp: 1, category: 'execution:completed', data: { command: 'whois', args: ['fixture.test'],
      output: '            Domain Name: FIXTURE.TEST\n            Registry Domain ID: fixture\n            Registrar WHOIS Server: fixture\nFourth' } };
    const lines = formatProjectLog(result).split('\n');
    expect(lines.slice(1, 4).every(line => line.startsWith('    ') && line[4] !== ' ')).toBe(true);
    expect(lines[4]).toBe('    + 1 lines (Ctrl+T full output)');
    expect(formatProjectLog(result, true).split('\n').slice(1, -1).every(line => line.startsWith('    '))).toBe(true);
  });
  it('pairs overlapping AI questions and answers by request ID and redacts private content', () => {
    const event = (category: string, data: Record<string, unknown>) => ({ timestamp: 1, category, data });
    const events = [event('provider:request', { requestId: 'one', provider: 'codex', model: 'primary', messages: [{ role: 'user', content: 'QUESTION_ONE token=private-fixture' }] }),
      event('provider:request', { requestId: 'two', provider: 'codex', model: 'primary', messages: [{ role: 'user', content: 'QUESTION_TWO' }] }),
      event('provider:response', { requestId: 'two', provider: 'local', model: 'fallback', response: { content: 'ANSWER_TWO' } }),
      event('provider:response', { requestId: 'one', provider: 'codex', model: 'primary', response: { content: 'ANSWER_ONE' } })];
    const history = formatAIHistory(events);
    expect(history.indexOf('QUESTION_ONE')).toBeLessThan(history.indexOf('ANSWER_ONE'));
    expect(history.indexOf('ANSWER_ONE')).toBeLessThan(history.indexOf('QUESTION_TWO'));
    expect(history).toContain('ANSWER · local/fallback'); expect(history).not.toContain('private-fixture');
    expect(formatAIHistory(events.slice(0, 1))).toContain('Awaiting response');
    expect(formatProjectLog(events[0], true)).toBe('');
  });
  it('uses readable units and shows measured process duration beside every exit code', () => {
    expect([59000, 60000, 754000, 3600000, 90000000].map(formatDuration)).toEqual(['59s', '1m 0s', '12m 34s', '1h 0m', '1d 1h']);
    const event = { timestamp: 1, category: 'execution:completed', data: { command: 'nmap', args: ['fixture.test'], durationMs: 125000, exitCode: 0, success: true } };
    expect(formatProjectLog(event)).toContain(' · 2m 5s · exit 0');
    expect(formatProjectLog({ ...event, category: 'execution:queued' })).toBe('');
  });
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
      id: 'internal-id', command: 'curl', args: ['--url', 'https://fixture.test/robots.txt', '-X', 'GET'],
    } };
    event.category = 'execution:started';
    const text = formatProjectLog(event, false, colors);
    expect(text).toContain(colors.command('curl'));
    expect(text).toContain(colors.argument('--url'));
    expect(text).toContain(colors.muted('https://fixture.test/robots.txt'));
    expect(stripVTControlCharacters(text)).toContain('Ran curl --url');
    expect(text.endsWith('\n')).toBe(true);
    expect(text).not.toContain('internal-id'); expect(text).not.toContain('"kind"');
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

  it('colors only commands, flags and quoted strings with gray or white output and no dots', () => {
    const colors = createTheme(2);
    const call = { timestamp: 1, category: 'execution:started', data: { command: 'curl', args: ['-u', 'user', '--retry=2', '-H', 'Accept: application/json', 'https://fixture.test'] } };
    const result = (success: boolean) => ({ timestamp: 2, category: 'scan:progress', data: { kind: 'tool_result', success, detail: 'First\nSecond' } });
    const brief = formatProjectLog(call, false, colors, 80, result(true));
    expect(brief).toContain(colors.foreground('Ran') + ' ' + colors.command('curl'));
    expect(brief).not.toContain('●');
    expect(brief).toContain(colors.argument('-u')); expect(brief).toContain(colors.muted('user'));
    expect(brief).toContain(colors.argument('--retry') + colors.muted('=2'));
    expect(colors.argument('-u')).not.toBe(colors.error('-u'));
    expect(brief).toContain(colors.success("'Accept: application/json'"));
    expect(brief).toContain(colors.muted('https://fixture.test'));
    expect(brief).toContain('    ' + colors.muted('First'));
    const full = formatProjectLog(call, true, colors, 80, result(false));
    expect(full).not.toContain('●');
    expect(full).toContain('    ' + colors.bright('First'));
    expect(full).not.toContain(colors.error('First'));
  });

  it('does not invent shell commands for native tools or replay cached commands', () => {
    expect(formatProjectLog({ timestamp: 1, category: 'scan:progress', data: { kind: 'tool_call', toolName: 'technology_detect', detail: 'technology_detect {"url":"https://fixture.test"}' } })).toBe('');
    expect(formatProjectLog({ timestamp: 1, category: 'scan:progress', data: { kind: 'tool_result', toolName: 'technology_detect', detail: 'Native analysis' } })).toContain('Analyzed · technology detect');
    expect(formatProjectLog({ timestamp: 1, category: 'scan:progress', data: { kind: 'tool_result', executionTraced: true, detail: 'Already shown under actual argv' } })).toBe('');
    expect(formatProjectLog({ timestamp: 1, category: 'orchestration:event', data: { action: 'SKIPPED', reason: 'duplicate', toolName: 'technology_detect' } })).toBe('');
    expect(formatSavedProjectLog({ timestamp: 1, category: 'orchestration:event', data: { action: 'SKIPPED', reason: 'duplicate' } })).toContain('duplicate');
  });

  it('keeps the oldest running command ahead of concurrent planning and protocol noise', () => {
    const activity = new ProjectActivity();
    const emit = (category: string, data: Record<string, unknown> = {}) => activity.update({ timestamp: 1, category, data });
    emit('provider:activity', { state: 'started' }); emit('provider:activity', { state: 'started' });
    expect(activity.label).toBe('Thinking');
    emit('execution:started', { id: 'first', command: 'curl' });
    emit('execution:started', { id: 'second', command: 'nmap' });
    emit('provider:progress', { agent: 'codex', type: 'turn.started' });
    emit('scan:progress', { kind: 'thinking', callsign: 'Recon-2' });
    emit('provider:activity', { state: 'completed' });
    expect(activity.label).toBe('Working · curl');
    emit('execution:completed', { id: 'first' }); expect(activity.label).toBe('Working · nmap');
    emit('execution:cancelled', { id: 'second' }); expect(activity.label).toBe('Thinking');
    emit('provider:activity', { state: 'completed' }); expect(activity.label).toBe('Working');
    emit('provider:activity', { state: 'started' }); emit('project:paused');
    expect(activity.label).toBe('Working');
    expect(formatProjectLog({ timestamp: 1, category: 'provider:activity', data: { state: 'started' } })).toBe('');
  });

  it('labels incomplete and inapplicable phases truthfully', () => {
    const event = (previousOutcome: string) => ({ timestamp: 1, category: 'mission:phase_changed', data: { previousPhase: 'delivery', phase: 'actions_on_objectives', previousOutcome, reason: 'No validated finding exists.' } });
    expect(formatProjectLog(event('not_applicable'))).toContain('Impact validation not applicable');
    expect(formatProjectLog(event('incomplete'))).toContain('Impact validation incomplete');
    expect(formatProjectLog(event('not_applicable'))).not.toContain('completed');
  });

  it('names completed and newly active scan stages explicitly', () => {
    const text = formatProjectLog({ timestamp: 1, category: 'mission:phase_changed', data: { previousPhase: 'reconnaissance', phase: 'weaponization' } });
    expect(text).toBe('Recon completed\n\nStage: Scanning');
    expect(formatProjectLog({ timestamp: 1, category: 'project:completed', data: { phase: 'actions_on_objectives' } })).toContain('Reporting completed');
    expect(formatProjectLog({ timestamp: 1, category: 'project:completed', data: {} })).toBe('Scan completed');
  });

  it('shows partial completion and warnings instead of an unconditional successful completion', () => {
    const event = (completionStatus: string) => ({ timestamp: 1, category: 'project:completed', data: { phase: 'actions_on_objectives', completionStatus } });
    expect(formatProjectLog(event('PARTIALLY_COMPLETED'))).toContain('Scan partially completed · untested areas remain');
    expect(formatProjectLog(event('COMPLETED_WITH_WARNINGS'))).toContain('Scan completed with warnings');
    expect(formatProjectLog({ timestamp: 1, category: 'execution:progress', data: {} })).toBe('');
  });
});

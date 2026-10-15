import type { ProjectLogEvent } from '../projects/session.js';
import { redactSecrets } from '../redact.js';
import { terminalText, wrapTerminalText } from './terminal.js';
import type { TerminalTheme } from './theme.js';

export function phaseLabel(phase?: string): string {
  const names: Record<string, string> = { reconnaissance: 'Recon', weaponization: 'Scanning', delivery: 'Impact validation',
    exploitation: 'Exploitation', installation: 'Verification', command_and_control: 'Connection checks', actions_on_objectives: 'Reporting' };
  return phase ? names[phase] || phase.replace(/_/g, ' ') : 'Preparing';
}

export function formatSavedProjectLog(event: ProjectLogEvent): string {
  const safe = redactSecrets(event) as ProjectLogEvent;
  const data = fields(safe);
  const { detail, ...metadata } = data;
  return terminalText(`${new Date(safe.timestamp).toLocaleTimeString('de-DE', { hour12: false })} ${safe.category}\n`
    + (typeof detail === 'string' ? `${detail}\n${JSON.stringify(metadata, null, 2)}`
      : typeof safe.data === 'string' ? safe.data : JSON.stringify(safe.data, null, 2)));
}

function fields(event: ProjectLogEvent): Record<string, unknown> {
  return event.data && typeof event.data === 'object' ? event.data as Record<string, unknown> : {};
}

export function projectLogStyle(event: ProjectLogEvent, colors: TerminalTheme) {
  if (event.category === 'mission:phase_changed' || event.category === 'project:completed') return colors.foreground;
  return colors.muted;
}

export function projectActivity(event: ProjectLogEvent): string | undefined {
  const data = fields(event);
  if (event.category === 'execution:started') return `Working · ${data.command}`;
  if (event.category === 'execution:completed') return 'Working';
  if (event.category === 'provider:progress' && data.type === 'turn.started') return `Thinking · ${data.agent || data.provider || 'AI'}`;
  if (event.category === 'scan:progress') {
    if (data.kind === 'thinking') return `Thinking · ${data.callsign || 'AI'}`;
    if (data.kind === 'tool_call') return `Working · ${data.toolName || data.taskName || 'tool'}`;
    if (data.kind === 'task_started') return `Working · ${data.taskName || 'scan'}`;
    if (data.kind === 'tool_result' || data.kind === 'task_completed' || data.kind === 'task_failed') return 'Working';
  }
  if (event.category === 'provider:progress' && data.type === 'turn.completed') return 'Working';
  return undefined;
}

function toolInvocation(data: Record<string, unknown>): string {
  if (typeof data.command === 'string' && Array.isArray(data.args)) {
    const quote = (value: unknown) => /^[\w@%+=:,./-]+$/.test(String(value)) ? String(value) : "'" + String(value).replace(/'/g, "'\\''") + "'";
    return [quote(data.command), ...data.args.map(quote)].join(' ');
  }
  return '';
}

function outputPreview(text: string, transcript: boolean, columns: number): string {
  if (transcript) return text;
  const lines = wrapTerminalText(text, Math.max(1, columns - 4));
  return lines.length <= 3 ? lines.join('\n')
    : lines.slice(0, 3).join('\n') + `\n+ ${lines.length - 3} lines (Ctrl+T full output)`;
}

function logContent(event: ProjectLogEvent): { title: string; body?: string; command?: string } | undefined {
  const data = fields(event);
  const detail = typeof data.detail === 'string' ? data.detail : '';
  const operator = data.callsign ? ` · ${data.callsign}` : '';
  if (event.category === 'execution:started' || event.category === 'execution:completed') {
    return { title: 'Ran', command: toolInvocation(data), body: typeof data.output === 'string' ? data.output : undefined };
  }
  if (event.category === 'scan:progress') {
    if (data.kind === 'tool_call') return undefined;
    if (data.kind === 'tool_result') return data.executionTraced || data.cacheHit ? undefined
      : { title: `Analyzed · ${String(data.toolName || 'observation').replace(/_/g, ' ')}`, body: detail };
    if (data.kind === 'thinking' || data.kind === 'task_started') return undefined;
    if (data.kind === 'task_failed') return { title: `${detail === 'aborted: project pause' ? 'Paused' : 'Failed'}${operator} · ${data.taskName || 'task'}`, body: detail };
    if (data.kind === 'task_completed') {
      return /Findings:/.test(detail) ? { title: 'Findings', body: detail.slice(detail.indexOf('Findings:') + 9).trim() } : undefined;
    }
  }
  if (event.category === 'provider:progress' || event.category === 'provider:availability') return undefined;
  if (event.category === 'mission:phase_changed') {
    const outcome = data.previousOutcome === 'not_applicable' ? 'not applicable' : data.previousOutcome === 'incomplete' ? 'incomplete' : 'completed';
    return { title: `${data.previousPhase ? `${phaseLabel(String(data.previousPhase))} ${outcome}${data.reason ? ` · ${data.reason}` : ''}\n\n` : ''}Stage: ${phaseLabel(String(data.phase || ''))}` };
  }
  if (event.category === 'project:completed') return { title: `${typeof data.phase === 'string' ? `${phaseLabel(data.phase)} completed\n` : ''}Scan completed` };
  if (event.category === 'provider:fallback') return { title: `Fallback · ${data.fromProvider} → ${data.toProvider}`, body: String(data.reason || data.error || '') };
  if (event.category === 'recovery:blocked') return { title: `Recovery paused · ${data.taskName || 'operation'}`, body: String(data.error || '') };
  if (event.category === 'orchestration:event') {
    if (/^(SKIPPED|USED)$/.test(String(data.action)) && /duplicate|equivalent|cached|shared evidence/.test(String(data.reason))) return undefined;
    return /^(executed|failed|repeated)$/i.test(String(data.action)) ? undefined
      : { title: `${data.action || 'Evidence'} · ${data.toolName || 'tool'}`, body: `${data.reason || ''}${data.target ? ` · ${data.target}` : ''}` };
  }
  const body = detail || (typeof event.data === 'string' ? event.data : Object.entries(data)
    .filter(([key]) => !['id', 'projectId', 'taskId', 'operatorId', 'timestamp'].includes(key))
    .map(([key, value]) => `${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`).join('\n'));
  return { title: event.category.replace(/[:_]/g, ' '), body };
}

export function formatProjectLog(event: ProjectLogEvent, transcript = false, colors?: TerminalTheme, columns = 80, result?: ProjectLogEvent): string {
  const safe = redactSecrets(event) as ProjectLogEvent;
  const content = logContent(safe);
  if (!content) return '';
  const title = terminalText(content.title);
  const lines = [colors ? projectLogStyle(safe, colors)(title) : title];
  if (content.command) {
    let first = true;
    const tokens = terminalText(content.command).match(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s"']+|\s+/g) || [];
    const command = tokens.map(token => {
      if (!colors || /^\s+$/.test(token)) return token;
      if (first) { first = false; return colors.command(token); }
      if (/^["']/.test(token)) return colors.success(token);
      if (token.startsWith('-')) {
        const equal = token.indexOf('=');
        return equal < 0 ? colors.error(token) : colors.error(token.slice(0, equal)) + colors.muted(token.slice(equal));
      }
      return colors.muted(token);
    }).join('');
    const response = result ? redactSecrets(result) as ProjectLogEvent : safe;
    const failure = fields(response).success === false;
    const label = colors ? (failure ? colors.error : colors.foreground)('Ran') : 'Ran';
    const exit = failure && typeof fields(response).exitCode === 'number' ? ` · exit ${fields(response).exitCode}` : '';
    lines[0] = `${label} ${command}${colors ? colors.error(exit) : exit}`;
    if (result) {
      const data = fields(response);
      if (typeof data.output === 'string' || typeof data.detail === 'string') content.body = String(data.output ?? data.detail);
    }
  }
  if (content.body) {
    const body = outputPreview(terminalText(content.body), transcript, columns);
    const style = colors ? transcript ? colors.bright : colors.muted : (text: string) => text;
    lines.push(...body.split('\n').map(line => '    ' + style(line)));
  }
  if (content.command || content.body) lines.push('');
  return lines.join('\n');
}

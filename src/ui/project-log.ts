import type { ProjectLogEvent } from '../projects/session.js';
import { redactSecrets } from '../redact.js';
import { terminalText, wrapTerminalText } from './terminal.js';
import { severityStyle, type TerminalTheme } from './theme.js';

function fields(event: ProjectLogEvent): Record<string, unknown> {
  return event.data && typeof event.data === 'object' ? event.data as Record<string, unknown> : {};
}

export function projectLogStyle(event: ProjectLogEvent, colors: TerminalTheme) {
  const data = fields(event);
  const status = String(data.kind || data.action || event.category);
  if (data.kind === 'task_failed' && data.detail === 'aborted: project pause') return colors.muted;
  if (data.success === false || /error|failed|blocked/i.test(status)) return colors.error;
  if (/fallback|deferred|skipped/i.test(status)) return colors.warning;
  const finding = data.finding && typeof data.finding === 'object' ? data.finding as Record<string, unknown> : {};
  const severity = data.severity || finding.severity;
  if (typeof severity === 'string') return severityStyle(severity, colors);
  if (/completed|executed/i.test(status) || data.success === true) return colors.success;
  if (/thinking|started|progress/i.test(status)) return colors.active;
  return colors.muted;
}

export function projectActivity(event: ProjectLogEvent): string | undefined {
  const data = fields(event);
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
  const detail = String(data.detail || '');
  const name = String(data.toolName || detail.split(' ')[0] || 'tool');
  let parameters: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(detail.slice(detail.indexOf(' ') + 1));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) parameters = parsed as Record<string, unknown>;
  } catch { return detail || name; }
  const args = Object.entries(parameters).map(([key, value]) => {
    const text = typeof value === 'string' ? terminalText(value).replace(/\n/g, ' ') : JSON.stringify(value);
    return `--${key} ${typeof text === 'string' && /\s/.test(text) ? JSON.stringify(text) : text}`;
  });
  return [name, ...args].join(' ');
}

function outputPreview(text: string, transcript: boolean, columns: number): string {
  if (transcript) return text;
  const lines = wrapTerminalText(text, Math.max(1, columns - 4));
  return lines.length <= 3 ? lines.join('\n')
    : lines.slice(0, 3).join('\n') + `\n+ ${lines.length - 3} lines (Ctrl+T full output)`;
}

function logContent(event: ProjectLogEvent, transcript: boolean): { title: string; body?: string; command?: string } | undefined {
  const data = fields(event);
  const detail = typeof data.detail === 'string' ? data.detail : '';
  const operator = data.callsign ? ` · ${data.callsign}` : '';
  if (event.category === 'scan:progress') {
    if (data.kind === 'tool_call') return { title: `Ran${operator}`, command: toolInvocation(data) };
    if (data.kind === 'tool_result') return { title: `${data.success === false ? 'Failed' : 'Result'} · ${data.toolName || 'tool'}${operator}`, body: detail };
    if (data.kind === 'thinking') return { title: `Thinking${operator}`, body: detail };
    if (data.kind === 'task_started') return { title: `Working${operator} · ${data.taskName || detail}` };
    if (data.kind === 'task_failed') return { title: `${detail === 'aborted: project pause' ? 'Paused' : 'Failed'}${operator} · ${data.taskName || 'task'}`, body: detail };
    if (data.kind === 'task_completed') return { title: `Done${operator} · ${data.taskName || 'task'}`, body: detail };
  }
  if (event.category === 'provider:progress') {
    const name = data.agent || data.provider || 'AI';
    if (data.type === 'thread.started' && !transcript) return undefined;
    const title = data.type === 'turn.started' ? 'Thinking' : data.type === 'turn.completed' ? 'Thought complete'
      : data.type === 'item.completed' ? 'Plan received' : 'AI working';
    return { title: `${title} · ${name}`, body: transcript && typeof data.text === 'string' ? data.text : undefined };
  }
  if (event.category === 'provider:fallback') return { title: `Fallback · ${data.fromProvider} → ${data.toProvider}`, body: String(data.reason || data.error || '') };
  if (event.category === 'provider:availability') return { title: `Provider · ${data.active && typeof data.active === 'object' ? (data.active as Record<string, unknown>).provider : data.provider || 'configured'}` };
  if (event.category === 'orchestration:event') return { title: `${data.action || 'Evidence'} · ${data.toolName || 'tool'}`, body: `${data.reason || ''}${data.target ? ` · ${data.target}` : ''}` };
  const body = detail || (typeof event.data === 'string' ? event.data : Object.entries(data)
    .filter(([key]) => !['id', 'projectId', 'taskId', 'operatorId', 'timestamp'].includes(key))
    .map(([key, value]) => `${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`).join('\n'));
  return { title: event.category.replace(/[:_]/g, ' '), body };
}

export function formatProjectLog(event: ProjectLogEvent, transcript = false, colors?: TerminalTheme, columns = 80): string {
  const safe = redactSecrets(event) as ProjectLogEvent;
  const content = logContent(safe, transcript);
  if (!content) return '';
  const time = new Date(event.timestamp).toLocaleTimeString('de-DE', { hour12: false });
  const title = `${time} ${terminalText(content.title)}`;
  const lines = [colors ? projectLogStyle(safe, colors)(title) : title];
  if (content.command) {
    const tokens = terminalText(content.command).match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) || [];
    const command = tokens.map((token, index) => !colors ? token : index === 0 ? colors.accent(token)
      : token.startsWith('-') ? colors.secondary(token) : colors.detail(token)).join(' ');
    lines.push('  ' + command);
  }
  if (content.body) {
    const body = outputPreview(terminalText(content.body), transcript, columns);
    const failed = fields(safe).success === false || /error|failed|blocked/.test(event.category);
    const style = colors ? failed ? projectLogStyle(safe, colors) : colors.muted : (text: string) => text;
    lines.push(...body.split('\n').map(line => '  └ ' + style(line)));
  }
  return lines.join('\n');
}

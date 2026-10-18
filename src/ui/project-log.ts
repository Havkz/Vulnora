import type { ProjectLogEvent } from '../projects/session.js';
import { redactSecrets } from '../redact.js';
import { terminalText, wrapTerminalText } from './terminal.js';
import type { TerminalTheme } from './theme.js';

const WEBSITE_STAGES = ['reconnaissance', 'weaponization', 'delivery', 'actions_on_objectives'];

export function phasePath(phase: string | undefined, colors: TerminalTheme): string {
  const stages = WEBSITE_STAGES.includes(phase || '') || !phase ? WEBSITE_STAGES
    : ['reconnaissance', 'weaponization', 'delivery', 'exploitation', 'installation', 'command_and_control', 'actions_on_objectives'];
  const styles = [colors.command, colors.active, colors.warning, colors.secondary, colors.success, colors.detail, colors.bright];
  return stages.map((stage, index) => {
    const label = stage === phase ? `[${phaseLabel(stage)}]` : phaseLabel(stage);
    return (stage === phase ? colors.emphasis : (text: string) => text)(styles[index](label));
  }).join(colors.muted(' -> '));
}

export function formatAIHistory(events: ProjectLogEvent[]): string {
  const requests = new Map<string, { timestamp: number; data: Record<string, unknown>; answer?: Record<string, unknown> }>();
  for (const event of events) {
    const data = fields(event);
    if (event.category === 'provider:request') requests.set(String(data.requestId), { timestamp: event.timestamp, data });
    if (event.category === 'provider:response') {
      const request = requests.get(String(data.requestId));
      if (request) request.answer = data;
    }
  }
  if (!requests.size) {
    const legacy = events.filter(event => event.category === 'provider:progress' && typeof fields(event).text === 'string');
    return 'Earlier versions saved responses only; their questions were not recorded. Full question/answer history begins with this version.\n\n'
      + (legacy.map(event => {
        const data = fields(event);
        return terminalText(String(redactSecrets(`ANSWER · ${data.provider || data.agent}/${data.model || 'unknown model'}\n${data.text}`)));
      }).join('\n\n') || 'No recorded AI questions or answers yet.');
  }
  return [...requests.values()].map(({ timestamp, data, answer }, index) => {
    const messages = Array.isArray(data.messages) ? data.messages as { role: string; content: string; toolCalls?: unknown }[] : [];
    const question = messages.map(message => `${message.role.toUpperCase()}\n${message.content}${message.toolCalls ? `\nTool calls: ${JSON.stringify(message.toolCalls)}` : ''}`).join('\n\n');
    const response = answer?.response as { content?: string; toolCalls?: unknown } | undefined;
    return `Request ${index + 1} · ${new Date(timestamp).toLocaleTimeString('de-DE')} · ${data.provider}/${data.model}\n\nQUESTION\n${question}\n\nTOOLS\n${JSON.stringify(data.tools || [], null, 2)}\n\nANSWER · ${answer?.provider || data.provider}/${answer?.model || data.model}\n`
      + (response ? `${response.content || ''}${response.toolCalls ? `\nTool calls: ${JSON.stringify(response.toolCalls, null, 2)}` : ''}` : String(answer?.error || (answer ? 'Request ended without a response.' : 'Awaiting response…')));
  }).map(text => terminalText(String(redactSecrets(text)))).join('\n\n────────────────────\n\n');
}

export function phaseLabel(phase?: string): string {
  const names: Record<string, string> = { reconnaissance: 'Recon', weaponization: 'Scanning', delivery: 'Impact validation',
    exploitation: 'Exploitation', installation: 'Verification', command_and_control: 'Connection checks', actions_on_objectives: 'Reporting' };
  return phase ? names[phase] || phase.replace(/_/g, ' ') : 'Preparing';
}

export function formatDuration(milliseconds: number): string {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m`;
  return `${Math.floor(seconds / 86400)}d ${Math.floor(seconds % 86400 / 3600)}h`;
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
  if (event.category === 'mission:phase_changed' || event.category === 'project:completed' || event.category === 'scan:progress') return colors.foreground;
  return colors.muted;
}

/** Running commands own the status until exit; background planning cannot replace them. */
export class ProjectActivity {
  private processes = new Map<string, string>();
  private thinking = 0;

  update(event: ProjectLogEvent): void {
    const data = fields(event);
    if (event.category === 'execution:started') this.processes.set(String(data.id), String(data.command));
    if (event.category === 'execution:completed' || event.category === 'execution:cancelled') this.processes.delete(String(data.id));
    if (event.category === 'provider:activity') this.thinking = Math.max(0, this.thinking + (data.state === 'started' ? 1 : -1));
    if (event.category === 'project:paused' || event.category === 'project:completed' || event.category === 'project:closed') this.reset();
  }

  get label(): string {
    const command = this.processes.values().next().value;
    return command ? `Working · ${command}` : this.thinking ? 'Thinking' : 'Working';
  }

  reset(): void { this.processes.clear(); this.thinking = 0; }
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
  if (event.category === 'execution:queued' || event.category === 'execution:cancelled' || event.category === 'execution:progress') return undefined;
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
  if (['provider:progress', 'provider:availability', 'provider:activity', 'provider:request', 'provider:response'].includes(event.category)) return undefined;
  if (event.category === 'mission:phase_changed') {
    const outcome = data.previousOutcome === 'not_applicable' ? 'not applicable' : data.previousOutcome === 'incomplete' ? 'incomplete' : 'completed';
    return { title: `${data.previousPhase ? `${phaseLabel(String(data.previousPhase))} ${outcome}${data.reason ? ` · ${data.reason}` : ''}\n\n` : ''}Stage: ${phaseLabel(String(data.phase || ''))}` };
  }
  if (event.category === 'project:completed') {
    const status = data.completionStatus;
    const outcome = status === 'PARTIALLY_COMPLETED' ? 'Scan partially completed · untested areas remain'
      : status === 'COMPLETED_WITH_WARNINGS' ? 'Scan completed with warnings'
        : status === 'BLOCKED' ? 'Scan blocked' : status === 'FAILED' ? 'Scan failed' : 'Scan completed';
    return { title: `${typeof data.phase === 'string' ? `${phaseLabel(data.phase)} completed\n` : ''}${outcome}` };
  }
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
        return equal < 0 ? colors.argument(token) : colors.argument(token.slice(0, equal)) + colors.muted(token.slice(equal));
      }
      return colors.muted(token);
    }).join('');
    const response = result ? redactSecrets(result) as ProjectLogEvent : safe;
    const failure = fields(response).success === false;
    const label = colors ? (failure ? colors.error : colors.foreground)('Ran') : 'Ran';
    const data = fields(response);
    const exit = typeof data.exitCode === 'number' ? ` · exit ${data.exitCode}` : '';
    const duration = typeof data.durationMs === 'number' ? data.durationMs : result ? result.timestamp - safe.timestamp : undefined;
    const elapsed = duration === undefined ? '' : ` · ${formatDuration(duration)}`;
    lines[0] = `${label} ${command}${colors ? colors.muted(elapsed) + (failure ? colors.error(exit) : colors.muted(exit)) : elapsed + exit}`;
    if (result) {
      const data = fields(response);
      if (typeof data.output === 'string' || typeof data.detail === 'string') content.body = String(data.output ?? data.detail);
    }
  }
  if (content.body) {
    // Normalize scanner padding before adding the same hanging indent to every output line.
    const raw = terminalText(content.body).split('\n');
    const margin = raw.find(line => line.trim())?.match(/^ */)?.[0].length || 0;
    const text = raw.map(line => line.slice(Math.min(margin, line.match(/^ */)?.[0].length || 0))).join('\n');
    const body = outputPreview(text, transcript, columns);
    const style = colors ? transcript ? colors.bright : colors.muted : (text: string) => text;
    const indent = '    ';
    lines.push(...body.split('\n').map(line => indent + style(line)));
  }
  if (content.command || content.body) lines.push('');
  return lines.join('\n');
}

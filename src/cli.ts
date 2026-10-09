#!/usr/bin/env node
/**
 * T3MP3ST CLI
 *
 * Command-line interface for T3MP3ST operations.
 */

import { Command } from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import boxen from 'boxen';
import ora from 'ora';
import Table from 'cli-table3';
import gradient from 'gradient-string';
import figlet from 'figlet';
import { shouldPrintOrchestrationEvent } from './live-log-policy.js';

import {
  createAutoTempest,
  createTestTempest,
  createStealthOperation,
  createAggressiveOperation,
  getBanner,
  type Tempest,
  type OperatorArchetype,
  type ScanProgressEvent,
} from './index.js';

import {
  config,
  hasApiKey,
  setApiKey,
  getConfiguredProviders,
  AVAILABLE_MODELS,
} from './config/index.js';

import { LLMBackbone } from './llm/index.js';
import { createOllamaSession } from './llm/ollama-session.js';
import { redactLedgerText } from './redact.js';
import { formatTerminalReport } from './terminal-report.js';

// Undici can surface a peer-closed HTTP/2 stream as an uncaught socket event
// after the request promise has already been rejected. Keep a remote transport
// failure from terminating the interactive terminal; the affected tool result
// remains red and the operator loop can continue or retry.
process.on('uncaughtException', (error) => {
  console.error(`[T3MP3ST] uncaught transport error: ${error instanceof Error ? error.message : String(error)}`);
});
process.on('unhandledRejection', (reason) => {
  console.error(`[T3MP3ST] unhandled transport rejection: ${reason instanceof Error ? reason.message : String(reason)}`);
});

// =============================================================================
// DISPLAY HELPERS
// =============================================================================

function showBanner(): void {
  try {
    const text = figlet.textSync('T3MP3ST', {
      font: 'ANSI Shadow',
      horizontalLayout: 'default',
    });
    console.log(gradient.pastel.multiline(text));
  } catch {
    console.log(chalk.cyan(getBanner()));
  }
  console.log(chalk.gray('  Tactical Execution Multi-agent Platform for Elite Security Testing\n'));
}

function showBox(title: string, content: string, borderColor: string = 'cyan'): void {
  console.log(
    boxen(content, {
      title,
      titleAlignment: 'center',
      padding: 1,
      margin: { top: 0, bottom: 1, left: 1, right: 1 },
      borderStyle: 'round',
      borderColor: borderColor as any,
    })
  );
}

function showSuccess(message: string): void {
  console.log(chalk.green('✓ ') + message);
}

function showError(message: string): void {
  console.log(chalk.red('✗ ') + message);
}

function showInfo(message: string): void {
  console.log(chalk.blue('ℹ ') + message);
}

function showWarning(message: string): void {
  console.log(chalk.yellow('⚠ ') + message);
}

// =============================================================================
// LIVE TERMINAL LOGS
// =============================================================================

function formatLiveDetail(value: unknown, limit = 2000): string {
  return redactLedgerText(String(value ?? '').replace(/\s+/g, ' ').trim(), limit);
}

type LiveLogController = {
  enabled: boolean;
};

const liveLogControllers = new WeakMap<Tempest, LiveLogController>();

// Keep event details close to neutral gray. The small hue shift groups each
// detail with its label without turning a full terminal row into a color block.
const liveDetailColors = {
  cyan: chalk.hex('#72a2a2'),
  magenta: chalk.hex('#a278a2'),
  blue: chalk.hex('#7096b3'),
  green: chalk.hex('#78a178'),
  yellow: chalk.hex('#aa985c'),
  red: chalk.hex('#aa7474'),
};

function printLiveLine(
  label: string,
  detail: unknown,
  color: (text: string) => string,
  context = '',
  timestamp = Date.now(),
  detailColor: (text: string) => string = chalk.dim
): void {
  const time = new Date(timestamp).toLocaleTimeString('de-DE', { hour12: false });
  const labelWidth = 15;
  const terminalWidth = Math.max(60, Math.min(240, process.stdout.columns || 120));
  const prefixWidth = time.length + 1 + labelWidth + 1;
  const raw = formatLiveDetail(context ? `${context} · ${detail}` : detail, 10000);
  const available = Math.max(12, terminalWidth - prefixWidth);
  const compact = raw.length > available ? `${raw.slice(0, Math.max(1, available - 1))}…` : raw;
  console.log(`${chalk.gray(time)} ${color(label.padEnd(labelWidth))} ${detailColor(compact)}`);
}

function toolDisplayName(toolName?: string): string {
  const labels: Record<string, string> = {
    nmap_scan: 'Nmap',
    port_scan: 'Port scan',
    curl_request: 'Curl',
    http_request: 'HTTP',
    dns_lookup: 'DNS',
    ssl_scan: 'TLS',
    nuclei_scan: 'Nuclei',
    technology_detect: 'Technology',
    version_detect: 'Version',
    robots_txt_fetch: 'Robots.txt',
    header_analysis: 'Headers',
    csp_analysis: 'CSP',
    cookie_analysis: 'Cookies',
    subdomain_enum: 'Subdomains',
    reverse_dns: 'Reverse DNS',
    whois_lookup: 'WHOIS',
    api_endpoint_discovery: 'API discovery',
    open_redirect_test: 'Redirect test',
    clickjacking_test: 'Clickjacking',
    http_methods_test: 'HTTP methods',
    network_trace: 'Network trace',
  };
  return labels[toolName || ''] || (toolName || 'Tool').replace(/_/g, ' ');
}

function describeToolCall(toolName: string | undefined, args: Record<string, unknown>): string {
  const label = toolDisplayName(toolName);
  try {
    const candidateTarget = String(args.target || args.url || args.domain || args.host || '').trim();
    const rawTarget = /^(?:null|undefined)(?:\d+)?$/i.test(candidateTarget) ? '' : candidateTarget;
    let target = rawTarget;
    try {
      const parsed = new URL(rawTarget);
      target = `${parsed.origin}${parsed.pathname}`;
    } catch {
      // Bare hosts and IP addresses are already compact.
    }
    if (target.length > 64) target = `${target.slice(0, 63)}…`;
    const rawPorts = String(args.ports || '').trim();
    const portParts = rawPorts.split(',').filter(Boolean);
    const ports = rawPorts.length > 32
      ? `${portParts.slice(0, 4).join(',')}… (${portParts.length} entries)`
      : rawPorts;
    const method = String(args.method || '').trim().toUpperCase();
    const recordType = String(args.type || '').trim().toUpperCase();

    if (toolName === 'nmap_scan' || toolName === 'port_scan') {
      const action = ports ? `ports ${ports}` : 'service scan';
      return `${label} - ${action}${target ? ` on ${target}` : ''}`;
    }
    if (toolName === 'dns_lookup') {
      return `${label} - ${recordType || 'lookup'}${target ? ` ${target}` : ''}`;
    }
    if (toolName === 'curl_request' || toolName === 'http_request') {
      return `${label} - ${method || 'request'}${target ? ` ${target}` : ''}`;
    }
    return `${label}${target ? ` - ${target}` : ''}`;
  } catch {
    return label;
  }
}

function activeToolDescription(event: ScanProgressEvent): string {
  try {
    const jsonStart = event.detail.indexOf('{');
    if (jsonStart < 0) return toolDisplayName(event.toolName);
    const args = JSON.parse(event.detail.slice(jsonStart)) as Record<string, unknown>;
    return describeToolCall(event.toolName, args);
  } catch {
    return toolDisplayName(event.toolName);
  }
}

function compactThinkingDetail(detail: string): string {
  try {
    const jsonStart = detail.indexOf('{');
    const jsonEnd = detail.lastIndexOf('}');
    if (jsonStart < 0 || jsonEnd < jsonStart) return detail;
    const parsed = JSON.parse(detail.slice(jsonStart, jsonEnd + 1)) as {
      tool_calls?: Array<{ name?: string; arguments?: Record<string, unknown> }>;
    };
    if (!parsed.tool_calls?.length) return detail;
    const counts = new Map<string, number>();
    for (const call of parsed.tool_calls) {
      const label = toolDisplayName(call.name);
      counts.set(label, (counts.get(label) || 0) + 1);
    }
    const tools = [...counts.entries()].map(([name, count]) => count > 1 ? `${name} ×${count}` : name).join(', ');
    return `Planning ${parsed.tool_calls.length} tool call(s): ${tools}`;
  } catch {
    return detail;
  }
}

function compactToolResult(event: ScanProgressEvent): string {
  const label = toolDisplayName(event.toolName);
  const detail = formatLiveDetail(event.detail, 2000);
  const shorten = (value: string, limit = 100): string =>
    value.length > limit ? `${value.slice(0, limit - 1)}…` : value;

  if (event.success === false && isTargetFetchFailure(event.toolName, detail)) {
    return `${label} - unreachable`;
  }

  if (/^SCOPE DENIED:/i.test(detail)) {
    const target = detail.match(/target ['"]([^'"]+)['"]/i)?.[1];
    return `${label} - scope denied${target ? ` for ${target}` : ''}`;
  }
  // A valid network tool invocation can fail because the remote endpoint, DNS, TLS,
  // or an intermediary is unavailable. That is useful scan evidence, but not a
  // local tool/argument failure. Keep the detail compact and let the caller color
  // this as a normal RESULT.
  if (event.success === false) {
    const exit = detail.match(/exit\s+([^):\s]+)/i)?.[1];
    const timeout = /timed?\s*out|timeout/i.test(detail);
    const reason = timeout ? 'timeout' : shorten(detail.replace(/^.*?failed(?: after \d+ attempt\(s\))?[: ]+/i, ''), 80);
    return `${label} - failed${exit ? ` (exit ${exit})` : ''} · ${reason}`;
  }

  if (event.toolName === 'nmap_scan') {
    const openPorts = detail.match(/\b\d+\/tcp\s+open\b/gi)?.length || 0;
    return `${label} - completed · ${openPorts} open port(s)`;
  }
  if (event.toolName === 'port_scan') {
    const openPorts = detail.match(/Open ports:\s*(\d+)/i)?.[1];
    const scanned = detail.match(/\((\d+) ports scanned/i)?.[1];
    return `${label} - completed${scanned ? ` · ${scanned} scanned` : ''}${openPorts ? ` · ${openPorts} open` : ''}`;
  }
  if (event.toolName === 'curl_request') {
    const status = detail.match(/HTTP\/\S+\s+\d{3}/i)?.[0];
    return `${label} - ${status || shorten(detail, 90)}`;
  }
  if (event.toolName === 'http_request') {
    const request = detail.match(/^HTTP\s+(\S+)\s+(\S+)\s+Status:\s*([^ ]+)/i);
    return request
      ? `${label} - ${request[1].toUpperCase()} ${shorten(request[2], 60)} · status ${request[3]}`
      : `${label} - ${shorten(detail, 90)}`;
  }
  if (event.toolName === 'dns_lookup' || event.toolName === 'reverse_dns') {
    return `${label} - ${shorten(detail.replace(/^DNS\s+/i, ''), 100)}`;
  }

  return `${label} - ${shorten(detail, 100)}`;
}

function isTargetFetchFailure(toolName: string | undefined, detail: string): boolean {
  const normalized = (toolName ?? '').replace(/_tool$/, '');
  // Resolver-side response failures are observations about the target's DNS
  // service (e.g. malformed/truncated replies), not a bad tool invocation.
  // Keep genuine adapter/runtime errors such as `records.join is not a
  // function` red while rendering these target-dependent DNS failures green.
  if ((normalized === 'dns_lookup' || normalized === 'reverse_dns') &&
      /query(?:txt|a|aaaa|cname|mx|ns|soa|srv|naptr|ptr|caa|any)\s+(?:e)?(?:badresp|servfail|refused)|\b(?:ebadresp|eservfail|erefused)\b/i.test(detail) &&
      !/records\.join|invalid argument|unknown option|usage:|child_process|process killed/i.test(detail)) {
    return true;
  }
  if ((normalized === 'dns_lookup' || normalized === 'reverse_dns') &&
      /(?:dns|lookup|query).*?(?:timeout|timed\s*out)|(?:timeout|timed\s*out).*?(?:dns|lookup|query)/i.test(detail) &&
      !/records\.join|invalid argument|unknown option|usage:|child_process|process killed/i.test(detail)) {
    return true;
  }
  if (normalized === 'curl_request' || normalized === 'curl' || normalized === 'ssl_scan' || normalized === 'tls' || normalized === 'testssl') return false;
  if (/process killed|child_process|stdio_maxbuffer|invalid argument|unknown option|usage:/i.test(detail)) return false;
  return /fetch failed|failed to fetch|operation was aborted|connection timed?\s*out|could not resolve host|tls connect error/i.test(detail);
}

function waitingSummary(
  tempest: Tempest,
  activeActivities: Map<string, { command: string }>
): string | null {
  const busy = tempest.command.getStatus().operators.busy;
  if (busy === 0) return null;
  const running = [...activeActivities.values()]
    .map((activity, index) => `${index + 1}. ${activity.command}`)
    .join(' · ');
  return `${busy} operator(s) busy${running ? ` · ${running}` : ''}`;
}

function printLiveEvent(event: ScanProgressEvent): void {
  const shortToolEvent = event.kind === 'tool_call' || event.kind === 'tool_result';
  const context = [event.callsign, shortToolEvent ? '' : event.taskName, event.source === 'backend_seeded' ? 'backend' : '']
    .filter(Boolean)
    .join(' · ');
  const policyDenied = event.kind === 'tool_result' && /^SCOPE DENIED:/i.test(event.detail);
  const orchestrationSkipped = event.kind === 'tool_result' && /ORCHESTRATOR (?:duplicate_skipped|redundant_skipped|budget_exceeded)/i.test(event.detail);
  const targetFetchFailure = event.kind === 'tool_result' && event.success === false && isTargetFetchFailure(event.toolName, event.detail);
  const labels: Record<ScanProgressEvent['kind'], {
    text: string;
    color: (text: string) => string;
    detailColor: (text: string) => string;
  }> = {
    task_started: { text: 'START', color: chalk.cyan.bold, detailColor: liveDetailColors.cyan },
    thinking: { text: 'THINK', color: chalk.magenta.bold, detailColor: liveDetailColors.magenta },
    tool_call: { text: 'TOOL', color: chalk.blue.bold, detailColor: liveDetailColors.blue },
    tool_result: {
      text: policyDenied ? 'DENIED' : orchestrationSkipped ? 'SKIPPED' : 'RESULT',
      color: policyDenied || orchestrationSkipped ? chalk.yellow.bold : event.success === false && !targetFetchFailure ? chalk.red.bold : chalk.green.bold,
      detailColor: policyDenied || orchestrationSkipped ? liveDetailColors.yellow : event.success === false && !targetFetchFailure ? liveDetailColors.red : liveDetailColors.green,
    },
    task_completed: {
      text: 'DONE',
      color: event.success === false ? chalk.yellow.bold : chalk.green.bold,
      detailColor: event.success === false ? liveDetailColors.yellow : liveDetailColors.green,
    },
    task_failed: { text: 'ERROR', color: chalk.red.bold, detailColor: liveDetailColors.red },
  };
  const label = labels[event.kind];
  const detail = event.kind === 'tool_call'
    ? activeToolDescription(event)
    : event.kind === 'tool_result'
      ? compactToolResult(event)
    : event.kind === 'thinking'
      ? compactThinkingDetail(event.detail)
      : event.detail;
  printLiveLine(label.text, detail, label.color, context, event.timestamp, label.detailColor);
}

function attachLiveLogs(tempest: Tempest): void {
  const controller: LiveLogController = { enabled: false };
  const pendingFallbackModels = new Map<string, number>();
  const activeActivities = new Map<string, { command: string }>();
  let lastLiveEventAt = Date.now();
  let idleWaitingShown = false;
  liveLogControllers.set(tempest, controller);
  tempest.command.on('scan:progress', event => {
    lastLiveEventAt = Date.now();
    idleWaitingShown = false;
    if (event.kind === 'task_started') {
      activeActivities.set(event.operatorId, { command: event.taskName || 'Starting task' });
    } else if (event.kind === 'thinking') {
      activeActivities.set(event.operatorId, { command: 'Thinking' });
    } else if (event.kind === 'tool_call') {
      activeActivities.set(event.operatorId, {
        command: activeToolDescription(event),
      });
    } else if (event.kind === 'tool_result') {
      activeActivities.set(event.operatorId, { command: `Processing ${toolDisplayName(event.toolName)} result` });
    } else if (['task_completed', 'task_failed'].includes(event.kind)) {
      activeActivities.delete(event.operatorId);
    }
    if (controller.enabled) {
      printLiveEvent(event);
      if (event.kind === 'task_completed' || event.kind === 'task_failed') {
        queueMicrotask(() => {
          if (!controller.enabled) return;
          const waiting = waitingSummary(tempest, activeActivities);
          if (waiting) printLiveLine('WAITING...', waiting, chalk.yellow.bold, '', Date.now(), liveDetailColors.yellow);
        });
      }
    }
  });

  // Only surface policy decisions here. Successful executions already have TOOL
  // and RESULT lines; printing EXECUTED again would make the live view noisier.
  tempest.command.on('orchestration:event', event => {
    if (!shouldPrintOrchestrationEvent(event.action)) return;
    lastLiveEventAt = Date.now();
    idleWaitingShown = false;
    if (!controller.enabled) return;
    const styles = {
      SKIPPED: { label: chalk.yellow.bold, detail: liveDetailColors.yellow },
      USED: { label: chalk.cyan.bold, detail: liveDetailColors.cyan },
      DEFERRED: { label: chalk.yellow.bold, detail: liveDetailColors.yellow },
      STOPPED: { label: chalk.red.bold, detail: liveDetailColors.red },
      REPEATED: { label: chalk.magenta.bold, detail: liveDetailColors.magenta },
      BLOCKED: { label: chalk.red.bold, detail: liveDetailColors.red },
      FAILED: { label: chalk.red.bold, detail: liveDetailColors.red },
      EXECUTED: { label: chalk.green.bold, detail: liveDetailColors.green },
    } as const;
    const style = styles[event.action as keyof typeof styles] || styles.FAILED;
    const compactTarget = event.target.length > 72 ? `${event.target.slice(0, 71)}…` : event.target;
    printLiveLine(
      event.action,
      `${event.reason} · ${compactTarget}`,
      style.label,
      toolDisplayName(event.toolName),
      event.timestamp,
      style.detail
    );
  });

  // Emit one compact snapshot per quiet period, not a repeating heartbeat. Any subsequent real
  // progress event arms the two-minute inactivity check again.
  const idleWaitingTimer = setInterval(() => {
    if (!controller.enabled || idleWaitingShown || Date.now() - lastLiveEventAt < 120_000) return;
    const waiting = waitingSummary(tempest, activeActivities);
    if (!waiting) return;
    printLiveLine('WAITING...', waiting, chalk.yellow.bold, '', Date.now(), liveDetailColors.yellow);
    idleWaitingShown = true;
  }, 15_000);
  idleWaitingTimer.unref();
  tempest.command.once('command:stopped', () => clearInterval(idleWaitingTimer));

  // A task-level DONE is intentionally compact because many of them appear during a
  // mission. Make the one mission-level completion unmistakable and emit it only after
  // MissionControl has completed every configured phase and stopped the command loop.
  tempest.mission.once('mission:completed', mission => {
    if (!controller.enabled) return;
    printLiveLine(
      'OPERATION DONE',
      `All phases completed · ${mission.name}`,
      chalk.bgGreen.black.bold,
      '',
      mission.completedAt ?? Date.now(),
      chalk.greenBright.bold
    );
  });

  tempest.llm.on('request:retry', ({ attempt, maxAttempts, error }) => {
    if (controller.enabled) printLiveLine('RETRY', error.message, chalk.yellow.bold, `${attempt}/${maxAttempts}`, Date.now(), liveDetailColors.yellow);
  });

  tempest.llm.on('request:refusal', ({ provider, model, preview }) => {
    if (controller.enabled) printLiveLine('REFUSED', preview, chalk.red.bold, `${provider}/${model}`, Date.now(), liveDetailColors.red);
  });

  tempest.llm.on('request:fallback', ({ fromModel, toModel, reason }) => {
    const recovered = String(reason || '').startsWith('recovered_after:');
    if (!recovered && toModel) {
      pendingFallbackModels.set(toModel, (pendingFallbackModels.get(toModel) || 0) + 1);
    }
    if (controller.enabled) {
      printLiveLine(
        recovered ? 'RECOVERED' : 'FALLBACK',
        `reason=${reason || 'unknown'}`,
        recovered ? chalk.green.bold : chalk.yellow.bold,
        `${fromModel} → ${toModel || 'none'}`,
        Date.now(),
        recovered ? liveDetailColors.green : liveDetailColors.yellow
      );
    }
  });

  tempest.llm.on('request:complete', ({ response, durationMs }) => {
    const pending = pendingFallbackModels.get(response.model) || 0;
    if (pending === 0) return;
    if (pending === 1) pendingFallbackModels.delete(response.model);
    else pendingFallbackModels.set(response.model, pending - 1);
    if (controller.enabled) printLiveLine('FALLBACK RESULT', response.content, chalk.green.bold, `${response.model} · ${durationMs} ms`, Date.now(), liveDetailColors.green);
  });

  tempest.llm.on('request:error', ({ error }) => {
    if (controller.enabled) printLiveLine('LLM ERROR', error.message, chalk.red.bold, '', Date.now(), liveDetailColors.red);
  });
}

function toggleLiveLogs(tempest: Tempest): void {
  const controller = liveLogControllers.get(tempest);
  if (!controller) return;
  controller.enabled = !controller.enabled;
  if (controller.enabled) {
    showSuccess('Live logs enabled (one compact line per event)');
  } else {
    showInfo('Live logs disabled');
  }
}

// =============================================================================
// STATUS DISPLAY
// =============================================================================

function displayStatus(tempest: Tempest): void {
  const status = tempest.command.getStatus();

  console.log('');
  console.log(chalk.bold.cyan('═══ OPERATION STATUS ═══'));
  console.log('');

  // Operation Info
  console.log(chalk.bold('Operation:'), status.name);
  console.log(chalk.bold('Status:'), status.running
    ? (status.paused ? chalk.yellow('PAUSED') : chalk.green('RUNNING'))
    : chalk.gray('STOPPED'));
  console.log(chalk.bold('Tick Count:'), status.tickCount);
  console.log('');

  // Operators Table
  const opTable = new Table({
    head: [
      chalk.cyan('Status'),
      chalk.cyan('Count'),
    ],
    style: { head: [], border: [] },
  });

  opTable.push(
    ['Available', chalk.green(status.operators.available.toString())],
    ['Busy', chalk.yellow(status.operators.busy.toString())],
    ['Cooldown', chalk.blue(status.operators.cooldown.toString())],
    ['Burned', chalk.red(status.operators.burned.toString())],
    [chalk.bold('Total'), chalk.bold(status.operators.total.toString())],
  );

  console.log(chalk.bold('Operators:'));
  console.log(opTable.toString());
  console.log('');

  // Findings Summary
  const findingsTable = new Table({
    head: [
      chalk.cyan('Severity'),
      chalk.cyan('Count'),
    ],
    style: { head: [], border: [] },
  });

  findingsTable.push(
    [chalk.red('Critical'), status.vault.bySeverity.critical.toString()],
    [chalk.magenta('High'), status.vault.bySeverity.high.toString()],
    [chalk.yellow('Medium'), status.vault.bySeverity.medium.toString()],
    [chalk.blue('Low'), status.vault.bySeverity.low.toString()],
    [chalk.gray('Info'), status.vault.bySeverity.info.toString()],
  );

  console.log(chalk.bold('Findings:'));
  console.log(findingsTable.toString());
  console.log('');

  // OPSEC Status
  const opsecColor = status.opsec.riskLevel === 'critical' ? chalk.red :
    status.opsec.riskLevel === 'high' ? chalk.yellow :
    status.opsec.riskLevel === 'medium' ? chalk.blue : chalk.green;

  console.log(chalk.bold('OPSEC:'), opsecColor(status.opsec.riskLevel.toUpperCase()));
  console.log(chalk.bold('Detections:'), `${status.opsec.activeDetections}/${status.opsec.totalDetections}`);

  if (status.opsec.abortRecommended) {
    console.log(chalk.red.bold('⚠ ABORT RECOMMENDED'));
  }

  console.log('');
}

// =============================================================================
// INTERACTIVE MODE
// =============================================================================

async function interactiveMode(): Promise<void> {
  showBanner();

  // Check for API keys
  const providers = getConfiguredProviders().filter(p => p !== 'mock');

  if (providers.length === 0) {
    showBox(
      'Setup Required',
      `No API keys configured. Please run setup first:

${chalk.cyan('npx t3mp3st setup')}

Or set environment variables:
${chalk.gray('OPENROUTER_API_KEY=your-key-here')}`,
      'yellow'
    );

    const { runSetup } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'runSetup',
        message: 'Would you like to run setup now?',
        default: true,
      },
    ]);

    if (runSetup) {
      // Run setup
      const { execSync } = await import('child_process');
      execSync('npx tsx src/setup.ts', { stdio: 'inherit' });
    }
    return;
  }

  // Welcome message
  showBox(
    'Welcome to T3MP3ST',
    `Configured providers: ${providers.map(p => chalk.cyan(p)).join(', ')}
Default: ${chalk.cyan(config.getLLMConfig().provider)} / ${chalk.cyan(config.getLLMConfig().model)}`,
    'cyan'
  );

  // Main menu loop
  let running = true;
  let tempest: Tempest | null = null;

  while (running) {
    const choices = [
      { name: '🚀 Start New Operation', value: 'new' },
    ];

    if (tempest) {
      const liveLogsOn = liveLogControllers.get(tempest)?.enabled === true;
      choices.push(
        { name: '📊 View Status', value: 'status' },
        { name: `📟 Live Logs (${liveLogsOn ? 'ON' : 'OFF'})`, value: 'live_logs' },
        { name: '👤 Spawn Operator', value: 'spawn' },
        { name: '🎯 Add Target', value: 'target' },
        { name: '📋 Create Mission', value: 'mission' },
        { name: '💬 Chat with AI', value: 'chat' },
        { name: '📝 Generate Report', value: 'report' },
        { name: '⏹️  Stop Operation', value: 'stop' },
      );
    }

    choices.push(
      { name: '⚙️  Settings', value: 'settings' },
      { name: '🚪 Exit', value: 'exit' },
    );

    const { action } = await inquirer.prompt([
      {
        type: 'list',
        name: 'action',
        message: tempest ? `[${tempest.command.name}] What would you like to do?` : 'What would you like to do?',
        choices,
      },
    ]);

    try {
      switch (action) {
        case 'new':
          tempest = await startNewOperation();
          break;
        case 'status':
          if (tempest) displayStatus(tempest);
          break;
        case 'live_logs':
          if (tempest) toggleLiveLogs(tempest);
          break;
        case 'spawn':
          if (tempest) await spawnOperator(tempest);
          break;
        case 'target':
          if (tempest) await addTarget(tempest);
          break;
        case 'mission':
          if (tempest) await createMission(tempest);
          break;
        case 'chat':
          if (tempest) await chatWithAI(tempest);
          break;
        case 'report':
          if (tempest) await generateReport(tempest);
          break;
        case 'stop':
          if (tempest) {
            tempest.command.stop();
            showSuccess('Operation stopped');
            tempest = null;
          }
          break;
        case 'settings':
          await openSettings();
          break;
        case 'exit':
          if (tempest) {
            const { confirmExit } = await inquirer.prompt([
              {
                type: 'confirm',
                name: 'confirmExit',
                message: 'Operation is running. Are you sure you want to exit?',
                default: false,
              },
            ]);
            if (!confirmExit) continue;
            tempest.command.stop();
          }
          running = false;
          break;
      }
    } catch (error) {
      showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  console.log(chalk.gray('\nGoodbye!\n'));
}

async function startNewOperation(): Promise<Tempest> {
  const { name, type } = await inquirer.prompt([
    {
      type: 'input',
      name: 'name',
      message: 'Operation name:',
      default: `Operation ${Date.now().toString(36).toUpperCase()}`,
    },
    {
      type: 'list',
      name: 'type',
      message: 'Operation type:',
      choices: [
        { name: 'Auto (use configured defaults)', value: 'auto' },
        { name: 'Stealth (minimal detection)', value: 'stealth' },
        { name: 'Aggressive (maximum speed)', value: 'aggressive' },
        { name: 'Test (mock LLM)', value: 'test' },
      ],
    },
  ]);

  const spinner = ora('Initializing operation...').start();

  let tempest: Tempest;

  switch (type) {
    case 'stealth':
      tempest = createStealthOperation(name);
      break;
    case 'aggressive':
      tempest = createAggressiveOperation(name);
      break;
    case 'test':
      tempest = createTestTempest(name);
      break;
    default:
      tempest = createAutoTempest(name);
  }

  attachLiveLogs(tempest);
  tempest.command.start();
  spinner.succeed(`Operation "${name}" started!`);

  displayStatus(tempest);

  return tempest;
}

async function spawnOperator(tempest: Tempest): Promise<void> {
  const archetypes: OperatorArchetype[] = [
    'recon', 'scanner', 'exploiter', 'infiltrator',
    'exfiltrator', 'ghost', 'coordinator', 'analyst',
  ];

  const { archetype, callsign } = await inquirer.prompt([
    {
      type: 'list',
      name: 'archetype',
      message: 'Select operator archetype:',
      choices: archetypes.map(a => ({
        name: `${a.charAt(0).toUpperCase() + a.slice(1)}`,
        value: a,
      })),
    },
    {
      type: 'input',
      name: 'callsign',
      message: 'Operator callsign:',
      default: (answers: { archetype: string }) =>
        `${answers.archetype.charAt(0).toUpperCase() + answers.archetype.slice(1)}-${tempest.cell.getAllOperators().length + 1}`,
    },
  ]);

  const operator = tempest.command.spawnOperator(callsign, archetype);
  showSuccess(`Operator ${callsign} (${archetype}) spawned!`);
  showInfo(`ID: ${operator.id}`);
}

async function addTarget(tempest: Tempest): Promise<void> {
  const { address, type, zone } = await inquirer.prompt([
    {
      type: 'input',
      name: 'address',
      message: 'Target address (URL or IP):',
      validate: (input: string) => input.length > 0 || 'Address is required',
    },
    {
      type: 'list',
      name: 'type',
      message: 'Target type:',
      choices: [
        'web_application',
        'api',
        'network',
        'host',
        'database',
        'cloud',
      ],
    },
    {
      type: 'list',
      name: 'zone',
      message: 'Target zone:',
      choices: ['external', 'dmz', 'internal', 'restricted'],
    },
  ]);

  const target = tempest.targetEnv.addTarget({
    name: address,
    type,
    zone,
    address,
  });

  showSuccess(`Target "${address}" added!`);
  showInfo(`ID: ${target.id}`);
}

async function createMission(tempest: Tempest): Promise<void> {
  const { name, objectives } = await inquirer.prompt([
    {
      type: 'input',
      name: 'name',
      message: 'Mission name:',
      default: 'Primary Mission',
    },
    {
      type: 'input',
      name: 'objectives',
      message: 'Objectives (comma-separated):',
      default: 'Enumerate attack surface, Identify vulnerabilities, Document findings',
    },
  ]);

  const mission = tempest.mission.createMission({
    name,
    objectives: objectives.split(',').map((o: string) => o.trim()),
  });

  tempest.mission.startMission(mission.id);

  showSuccess(`Mission "${name}" created and started!`);
  showInfo(`ID: ${mission.id}`);
}

async function chatWithAI(tempest: Tempest): Promise<void> {
  showInfo('Chat mode - type "exit" to return to menu\n');

  let chatting = true;

  while (chatting) {
    const { message } = await inquirer.prompt([
      {
        type: 'input',
        name: 'message',
        message: chalk.cyan('You:'),
        validate: (input: string) => input.length > 0 || 'Enter a message',
      },
    ]);

    if (message.toLowerCase() === 'exit') {
      chatting = false;
      continue;
    }

    const spinner = ora('Thinking...').start();

    try {
      const response = await tempest.llm.prompt(message);
      spinner.stop();
      console.log(chalk.green('AI:'), response);
      console.log('');
    } catch (error) {
      spinner.fail('Error');
      showError(`${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

async function generateReport(tempest: Tempest): Promise<void> {
  const mission = tempest.mission.getActiveMission();

  if (!mission) {
    // Create a temporary mission for report
    const tempMission = tempest.mission.createMission({
      name: 'Ad-hoc Report',
      objectives: ['Generate findings report'],
    });
    tempest.mission.startMission(tempMission.id);
  }

  try {
    const report = tempest.command.generateReport();
    console.log('');
    console.log(chalk.bold.cyan('═══ ENGAGEMENT REPORT ═══'));
    console.log('');
    console.log(formatTerminalReport(report));
  } catch (error) {
    showWarning('No findings to report yet.');
  }
}

async function openSettings(): Promise<void> {
  const { setting } = await inquirer.prompt([
    {
      type: 'list',
      name: 'setting',
      message: 'Settings:',
      choices: [
        { name: 'View current configuration', value: 'view' },
        { name: 'Change default provider', value: 'provider' },
        { name: 'Change default model', value: 'model' },
        { name: 'Add/update API key', value: 'apikey' },
        { name: 'Back', value: 'back' },
      ],
    },
  ]);

  switch (setting) {
    case 'view': {
      const settings = config.getAll();
      console.log('');
      console.log(chalk.bold('Current Configuration:'));
      console.log(chalk.cyan('  Provider:'), settings.defaultProvider);
      console.log(chalk.cyan('  Model:'), settings.defaultModel);
      console.log(chalk.cyan('  OpenRouter:'), hasApiKey('openrouter') ? chalk.green('configured') : chalk.red('not set'));
      console.log(chalk.cyan('  Venice:'), hasApiKey('venice') ? chalk.green('configured') : chalk.red('not set'));
      console.log(chalk.cyan('  Anthropic:'), hasApiKey('anthropic') ? chalk.green('configured') : chalk.red('not set'));
      console.log(chalk.cyan('  OpenAI:'), hasApiKey('openai') ? chalk.green('configured') : chalk.red('not set'));
      console.log(chalk.cyan('  DeepSeek:'), hasApiKey('deepseek') ? chalk.green('configured') : chalk.red('not set'));
      console.log('');
      break;
    }

    case 'provider': {
      const providers = getConfiguredProviders().filter(p => p !== 'mock');
      if (providers.length === 0) {
        showWarning('No API keys configured');
        break;
      }
      const { provider } = await inquirer.prompt([
        {
          type: 'list',
          name: 'provider',
          message: 'Select default provider:',
          choices: providers,
          default: config.get('defaultProvider'),
        },
      ]);
      config.setDefaultProvider(provider);
      showSuccess(`Default provider set to: ${provider}`);
      break;
    }

    case 'model': {
      const currentProvider = config.get('defaultProvider');
      const availableModels = AVAILABLE_MODELS[currentProvider];
      if (!availableModels || availableModels.length === 0) {
        showWarning(`No models available for ${currentProvider}`);
        break;
      }
      const { selectedModel } = await inquirer.prompt([
        {
          type: 'list',
          name: 'selectedModel',
          message: 'Select default model:',
          choices: availableModels.map(m => ({
            name: `${m.name} (${m.id}) - ${m.contextWindow.toLocaleString()} ctx`,
            value: m.id,
          })),
          default: config.get('defaultModel'),
        },
      ]);
      config.setDefaultModel(currentProvider, selectedModel);
      showSuccess(`Default model set to: ${selectedModel}`);
      break;
    }

    case 'apikey': {
      const { keyProvider } = await inquirer.prompt([
        {
          type: 'list',
          name: 'keyProvider',
          message: 'Which provider?',
          choices: ['openrouter', 'venice', 'anthropic', 'openai', 'deepseek'],
        },
      ]);
      const { apiKey } = await inquirer.prompt([
        {
          type: 'password',
          name: 'apiKey',
          message: `Enter ${keyProvider} API key:`,
          mask: '*',
        },
      ]);
      if (apiKey) {
        setApiKey(keyProvider, apiKey);
        showSuccess(`${keyProvider} API key saved!`);
      }
      break;
    }

  }
}

// =============================================================================
// CLI COMMANDS
// =============================================================================

const program = new Command();

program
  .name('t3mp3st')
  .description('T3MP3ST - Tactical Execution Multi-agent Platform for Elite Security Testing')
  .version('1.0.0');

program
  .command('interactive', { isDefault: true })
  .description('Start interactive mode')
  .action(interactiveMode);

program
  .command('setup')
  .description('Run the setup wizard')
  .action(async () => {
    const { execSync } = await import('child_process');
    try {
      execSync('npx tsx src/setup.ts', { stdio: 'inherit', cwd: process.cwd() });
    } catch {
      // Setup script handles its own errors
    }
  });

program
  .command('status')
  .description('Show current configuration status')
  .action(() => {
    showBanner();
    const settings = config.getAll();

    console.log(chalk.bold('Configuration Status:\n'));

    const table = new Table({
      style: { head: [], border: [] },
    });

    table.push(
      [chalk.cyan('Default Provider'), settings.defaultProvider],
      [chalk.cyan('Default Model'), settings.defaultModel],
      [chalk.cyan('OpenRouter API Key'), hasApiKey('openrouter') ? chalk.green('✓ Configured') : chalk.red('✗ Not set')],
      [chalk.cyan('Venice API Key'), hasApiKey('venice') ? chalk.green('✓ Configured') : chalk.red('✗ Not set')],
      [chalk.cyan('Anthropic API Key'), hasApiKey('anthropic') ? chalk.green('✓ Configured') : chalk.red('✗ Not set')],
      [chalk.cyan('OpenAI API Key'), hasApiKey('openai') ? chalk.green('✓ Configured') : chalk.red('✗ Not set')],
      [chalk.cyan('DeepSeek API Key'), hasApiKey('deepseek') ? chalk.green('✓ Configured') : chalk.red('✗ Not set')],
      [chalk.cyan('Config Path'), config.getConfigPath()],
    );

    console.log(table.toString());
    console.log('');
  });

program
  .command('test')
  .description('Test the LLM connection')
  .action(async () => {
    showBanner();

    const provider = config.getLLMConfig().provider;

    if (!['codex', 'local', 'local-agent', 'mock'].includes(provider) && !config.getLLMConfig().apiKey) {
      showError(`No API key configured for ${provider}`);
      showInfo('Run "npx t3mp3st setup" to configure API keys');
      process.exitCode = 1;
      return;
    }

    const spinner = ora(`Testing connection to ${provider}...`).start();

    try {
      const llm = new LLMBackbone(config.getLLMConfig());
      const response = await llm.prompt('Say "Connection successful!" and nothing else.');

      spinner.succeed('Connection successful!');
      console.log('');
      console.log(chalk.cyan('Response:'), response);
      console.log('');
    } catch (error) {
      spinner.fail('Connection failed');
      showError(`${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
    }
  });

program
  .command('models')
  .description('List available models')
  .action(() => {
    showBanner();

    const provider = config.get('defaultProvider');
    const models = AVAILABLE_MODELS[provider];

    console.log(chalk.bold(`Available models for ${provider}:\n`));

    const table = new Table({
      head: [chalk.cyan('Model ID'), chalk.cyan('Name'), chalk.cyan('Context')],
      style: { head: [], border: [] },
    });

    for (const model of models) {
      table.push([
        model.id,
        model.name,
        `${model.contextWindow.toLocaleString()} tokens`,
      ]);
    }

    console.log(table.toString());
    console.log('');
  });

// Wait for async commands so the model remains loaded until the CLI actually exits.
let ollamaSession: ReturnType<typeof createOllamaSession> | undefined;
program.hook('preAction', async (_program, command) => {
  if (!['interactive', 'test'].includes(command.name())) return;
  ollamaSession = createOllamaSession(config.getLLMConfig());
  showInfo('Preparing configured local fallback...');
  await ollamaSession.start();
});

async function releaseOllama(): Promise<void> {
  try { await ollamaSession?.stop(); }
  catch (error) { showWarning(`Could not unload Ollama: ${error instanceof Error ? error.message : String(error)}`); }
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => { void releaseOllama().finally(() => process.exit(signal === 'SIGINT' ? 130 : 143)); });
}

try { await program.parseAsync(); }
catch (error) {
  if (error instanceof Error && error.name === 'ExitPromptError') process.exitCode = 130;
  else {
    showError(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
} finally { await releaseOllama(); }

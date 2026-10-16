import { commandPath } from '../command-path.js';
import { CheckpointWriteError } from '../agent/checkpoint.js';
import { redactSecrets } from '../redact.js';
import { redactConfiguredSecrets } from '../arsenal/target-headers.js';
import { createHash } from 'crypto';
import { execFile } from 'child_process';
import { resolve4 } from 'dns/promises';
import { stat, statfs, readFile } from 'fs/promises';
import { DEFAULT_WEB_WORDLIST } from '../arsenal/catalog.js';
import { promisify } from 'util';
import type { CustomTool, ToolContext, ToolResult } from '../types/index.js';
import { evidenceStoreFromEnvironment, type EvidenceStore } from './evidence-store.js';
import { ScanPolicy } from './scan-policy.js';

const execFileAsync = promisify(execFile);

export type OrchestratedToolCategory =
  | 'passive_recon' | 'dns' | 'http_fetch' | 'http_analysis' | 'content_discovery'
  | 'active_validation' | 'exploit_validation' | 'port_discovery' | 'service_detection'
  | 'full_port_scan' | 'tls' | 'offline' | 'reporting' | 'other';

export type ToolErrorType =
  | 'configuration_error' | 'dependency_missing' | 'timeout' | 'network_unreachable'
  | 'waf_blocked' | 'rate_limited' | 'target_error' | 'tool_crash' | 'empty_result'
  | 'valid_negative_result' | 'budget_exceeded' | 'duplicate_skipped' | 'redundant_skipped'
  | 'scope_denied' | 'not_authorized' | 'aborted';

export type EvidenceStatus = 'success' | 'failed' | 'skipped' | 'deferred';
export type RepeatReason =
  | 'expired_cache' | 'previous_failure' | 'contradiction_verification'
  | 'independent_confirmation_required' | 'different_network_perspective'
  | 'materially_different_configuration';

export interface TargetBudgets {
  passive_recon_budget: number;
  baseline_http_budget: number;
  content_discovery_budget: number;
  active_validation_budget: number;
  exploit_validation_budget: number;
  total_request_budget: number;
  http_request_budget: number;
  port_probe_budget: number;
  batch_tool_budget: number;
  tool_call_budget: number;
}

export type ExecutionStatus = 'executed' | 'skipped' | 'deferred' | 'blocked' | 'failed';
export type ResultType = 'positive' | 'negative' | 'empty' | 'inconclusive' | 'error';
export type PolicyReason = 'scope_denied' | 'not_authorized' | 'budget_exceeded' | 'reporting_only';

export interface NormalizedToolCall {
  toolName: string;
  toolCategory: OrchestratedToolCategory;
  normalizedSignature: string;
  equivalentSignature: string;
  normalizedTarget: string;
  host: string;
  port?: number;
  scheme?: string;
  path?: string;
  method?: string;
  relevantParameters: Record<string, unknown>;
  scanDepth: string;
  toolConfiguration: Record<string, unknown>;
}

export interface NetworkContext {
  edgeSurface: boolean;
  edgeProvider?: string;
  blockState: 'clear' | 'defensive' | 'probable_edge_block';
  latencyMs?: number;
  consecutiveTimeouts: number;
  blockingResponses: number;
  scanning?: { behavior: NonNullable<ScanPolicy['behavior']>; limits: ReturnType<ScanPolicy['limits']> };
}

export interface EvidenceRecord {
  id: string;
  toolName: string;
  toolCategory: OrchestratedToolCategory;
  normalizedSignature: string;
  equivalentSignature: string;
  target: string;
  timestamp: number;
  requestParameters: Record<string, unknown>;
  rawOutput: string;
  parsedOutput?: Record<string, unknown>;
  status: EvidenceStatus;
  confidence: number;
  sourceAgent: string;
  responseStatus?: number;
  responseHeaders?: Record<string, string>;
  responseBodyHash?: string;
  responseFingerprint?: string;
  networkContext: NetworkContext;
  errorType?: ToolErrorType;
  repeatReason?: RepeatReason;
  result: ToolResult;
  executionStatus: ExecutionStatus;
  resultType: ResultType;
  policyReason?: PolicyReason;
  attemptId?: string;
  sourceToolCallId?: string;
  findingIds: string[];
  budgetCostEstimated: number;
  budgetCostActual?: number;
  budgetCostSource: 'tool_reported' | 'adapter_measured' | 'orchestrator_estimated';
}

export interface EvidenceConflict {
  target: string;
  subject: string;
  recordIds: string[];
  explanation: string;
  finalState: string;
  confidence: number;
  verificationRequired: boolean;
  recommendedVerification: string;
}

export interface OrchestratorMetrics {
  actualNetworkRequests: number;
  redundantRequestsAvoided: number;
  cacheHits: number;
  toolFailures: number;
  wafEvents: number;
  rateLimitEvents: number;
  blockedCalls: number;
  contradictions: number;
  incompleteAreas: string[];
  budgetCostEstimated: number;
  budgetCostActual: number;
  budgetCostSources: Record<'tool_reported' | 'adapter_measured' | 'orchestrator_estimated', number>;
}

export interface OrchestratorEvent {
  action: 'SKIPPED' | 'USED' | 'DEFERRED' | 'STOPPED' | 'REPEATED' | 'BLOCKED' | 'FAILED' | 'EXECUTED';
  reason: string;
  toolName: string;
  target: string;
  signature: string;
  timestamp: number;
}

const DEFAULT_BUDGETS: TargetBudgets = {
  passive_recon_budget: 70_000,
  baseline_http_budget: 20,
  content_discovery_budget: 180,
  active_validation_budget: 80,
  exploit_validation_budget: 30,
  total_request_budget: 70_500,
  http_request_budget: 500,
  port_probe_budget: 70_000,
  batch_tool_budget: 100,
  tool_call_budget: 500,
};

const HTTP_FETCH_TOOLS = new Set(['http_request', 'curl_request', 'curl_tool']);
const HTTP_ANALYSIS_TOOLS = new Set([
  'header_analysis', 'cookie_analysis', 'csp_analysis', 'clickjacking_test', 'technology_detect',
]);
const CONTENT_TOOLS = /^(?:dir_bruteforce|api_endpoint_discovery|ffuf_fuzz|ffuf_tool|gobuster_tool|feroxbuster_tool|katana_tool)$/;
const ACTIVE_TOOLS = /(?:nuclei|sqli|xss|ssti|lfi|redirect|cors|http_methods|nikto|sqlmap)/i;
const EXPLOIT_TOOLS = /(?:exploit|metasploit|msf|password_spray|hydra|command_exec|shell)/i;
const AGGRESSIVE_TOOLS = /(?:nuclei|ffuf|gobuster|ferox|katana|nikto|sqlmap|nmap|naabu|port_scan|dir_bruteforce)/i;
export const TOOL_BINARIES: Record<string, string> = {
  nmap_scan: 'nmap', nmap_tool: 'nmap', nuclei_scan: 'nuclei', ffuf_fuzz: 'ffuf',
  ffuf_tool: 'ffuf', curl_request: 'curl', curl_tool: 'curl', gobuster_tool: 'gobuster',
  feroxbuster_tool: 'feroxbuster', katana_tool: 'katana', naabu_tool: 'naabu',
  testssl_tool: 'testssl.sh', nikto_tool: 'nikto', wafw00f_tool: 'wafw00f',
};
const VERSION_ARGS: Record<string, string[]> = {
  nmap: ['--version'], nuclei: ['-version'], ffuf: ['-V'], curl: ['--version'],
  gobuster: ['version'], feroxbuster: ['--version'], katana: ['-version'], naabu: ['-version'],
  'testssl.sh': ['--version'], nikto: ['-Version'], wafw00f: ['--version'],
};

function stable(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, nested]) => [key, stable(nested)])
  );
  return value;
}

function hash(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function normalizedHeaders(value: unknown): Record<string, string> {
  if (value && typeof value === 'object' && !Array.isArray(value)) return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, nested]) => [key.toLowerCase(), String(nested).trim()]).sort(([a], [b]) => a.localeCompare(b))
  );
  if (typeof value !== 'string') return {};
  return Object.fromEntries(value.split(/,(?=[^,]+:)/).map(line => {
    const separator = line.indexOf(':');
    return separator > 0 ? [line.slice(0, separator).trim().toLowerCase(), line.slice(separator + 1).trim()] : null;
  }).filter((entry): entry is [string, string] => !!entry).sort(([a], [b]) => a.localeCompare(b)));
}

function normalizeUrl(raw: string, methodHint = 'GET'): { target: string; host: string; port?: number; scheme?: string; path?: string; method: string } {
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    const url = new URL(candidate);
    url.hostname = url.hostname.toLowerCase();
    url.hash = '';
    url.searchParams.sort();
    const scheme = url.protocol.replace(':', '');
    const port = url.port ? Number(url.port) : scheme === 'https' ? 443 : scheme === 'http' ? 80 : undefined;
    const path = `${url.pathname || '/'}${url.search}`;
    return { target: `${scheme}://${url.hostname}${url.port ? `:${url.port}` : ''}${path}`, host: url.hostname, port, scheme, path, method: methodHint.toUpperCase() };
  } catch {
    return { target: raw.trim().toLowerCase(), host: raw.trim().toLowerCase(), method: methodHint.toUpperCase() };
  }
}

function portSet(spec: unknown): number[] {
  if (Array.isArray(spec)) return [...new Set(spec.map(Number).filter(port => Number.isInteger(port) && port > 0 && port <= 65535))].sort((a, b) => a - b);
  if (typeof spec !== 'string') return [];
  const ports = new Set<number>();
  for (const part of spec.split(',').map(value => value.trim()).filter(Boolean)) {
    const range = part.match(/^(\d+)-(\d+)$/);
    if (range) {
      const start = Number(range[1]); const end = Number(range[2]);
      if (end - start > 65535) continue;
      for (let port = start; port <= end; port++) ports.add(port);
    } else if (/^\d+$/.test(part)) ports.add(Number(part));
  }
  return [...ports].filter(port => port > 0 && port <= 65535).sort((a, b) => a - b);
}

function classifyPortTool(toolName: string, parameters: Record<string, unknown>): OrchestratedToolCategory | null {
  if (!/^(?:port_scan|nmap_scan|nmap_tool|naabu_tool)$/.test(toolName)) return null;
  const ports = portSet(parameters.ports);
  const flags = String(parameters.flags || '');
  if (ports.length >= 60_000 || /(?:^|\s)-p-?(?:\s|$)|1-65535/.test(`${flags} ${String(parameters.ports || '')}`)) return 'full_port_scan';
  if (/(?:^|\s)-sV(?:\s|$)|version/i.test(flags)) return 'service_detection';
  return 'port_discovery';
}

export function toolCategory(toolName: string, parameters: Record<string, unknown> = {}, context?: ToolContext): OrchestratedToolCategory {
  if (context?.purpose === 'reporting') return 'reporting';
  const portCategory = classifyPortTool(toolName, parameters);
  if (portCategory) return portCategory;
  if (toolName === 'dns_lookup' || toolName === 'reverse_dns') return 'dns';
  if (HTTP_FETCH_TOOLS.has(toolName)) return 'http_fetch';
  if (HTTP_ANALYSIS_TOOLS.has(toolName)) return 'http_analysis';
  if (CONTENT_TOOLS.test(toolName)) return 'content_discovery';
  if (EXPLOIT_TOOLS.test(toolName)) return 'exploit_validation';
  if (ACTIVE_TOOLS.test(toolName)) return 'active_validation';
  if (/(?:ssl|tls|testssl)/i.test(toolName)) return 'tls';
  if (/(?:whois|subdomain|subfinder|amass|wayback)/i.test(toolName)) return 'passive_recon';
  if (/(?:decode|encode|hash_crack|cve_lookup)/i.test(toolName)) return 'offline';
  return 'other';
}

export function normalizeToolCall(toolName: string, context: ToolContext): NormalizedToolCall {
  const parameters = { ...(context.parameters || {}) };
  const rawTarget = String(parameters.url || parameters.target || parameters.host || parameters.domain || context.target?.address || 'local');
  const method = String(parameters.method || 'GET').toUpperCase();
  const url = normalizeUrl(rawTarget, method);
  const category = toolCategory(toolName, parameters, context);
  const ports = portSet(parameters.ports);
  const scanDepth = category === 'full_port_scan' ? 'full'
    : category === 'service_detection' ? 'service'
      : ports.length ? `${ports.length}_ports` : String(parameters.depth || parameters.wordlist || 'standard');
  const irrelevant = new Set(['timeout', 'max_time', 'retries']);
  const relevantParameters = Object.fromEntries(Object.entries(parameters)
    .filter(([key]) => !irrelevant.has(key))
    .map(([key, value]) => [key, key === 'ports' ? ports : value]));
  const toolConfiguration = Object.fromEntries(Object.entries(parameters)
    .filter(([key]) => irrelevant.has(key) || ['flags', 'severity', 'tags', 'wordlist'].includes(key)));
  const base = { category, target: url.target, host: url.host, port: url.port, scheme: url.scheme, path: url.path, method: url.method, relevantParameters, scanDepth, toolConfiguration };
  const normalizedSignature = hash(JSON.stringify(stable({ toolName, ...base })));
  let equivalentShape: Record<string, unknown> = { category, host: url.host, port: url.port, scheme: url.scheme, path: url.path, method: url.method, relevantParameters, scanDepth };
  if (category === 'http_fetch') {
    const requestBody = parameters.body ?? parameters.data;
    equivalentShape = { category, host: url.host, port: url.port, scheme: url.scheme, path: url.path, method: url.method, headers: normalizedHeaders(parameters.headers), bodyHash: requestBody ? hash(String(requestBody)) : '' };
  }
  if (category === 'dns') equivalentShape = {
    category,
    family: toolName === 'reverse_dns' ? 'reverse' : 'record_lookup',
    domain: url.host,
    type: String(parameters.type || 'A').toUpperCase(),
  };
  if (category === 'port_discovery' || category === 'service_detection' || category === 'full_port_scan') equivalentShape = { category, host: url.host, ports, scanDepth };
  if (category === 'content_discovery') {
    const family = /^(?:dir_bruteforce|ffuf_fuzz|ffuf_tool|gobuster_tool|feroxbuster_tool)$/.test(toolName)
      ? 'directory_enumeration'
      : toolName === 'api_endpoint_discovery' ? 'api_discovery' : toolName;
    equivalentShape = { category, family, host: url.host, port: url.port, scheme: url.scheme, path: url.path, method: url.method, relevantParameters, scanDepth };
  }
  if (!['http_fetch', 'dns', 'port_discovery', 'service_detection', 'full_port_scan', 'content_discovery'].includes(category)) {
    // Distinct analyzers and validators answer different questions even when they
    // use the same target. Keep their tool identity unless a family above declares
    // them functionally equivalent.
    equivalentShape = { ...equivalentShape, toolName };
  }
  return { toolName, toolCategory: category, normalizedSignature, equivalentSignature: hash(JSON.stringify(stable(equivalentShape))), normalizedTarget: url.target, host: url.host, port: url.port, scheme: url.scheme, path: url.path, method: url.method, relevantParameters, scanDepth, toolConfiguration };
}

function targetKey(target: string): string {
  return normalizeUrl(target).host || target.trim().toLowerCase();
}

function errorType(result: ToolResult): ToolErrorType | undefined {
  const declared = result.metadata?.orchestrationStatus;
  if (typeof declared === 'string' && [
    'configuration_error', 'dependency_missing', 'timeout', 'network_unreachable',
    'waf_blocked', 'rate_limited', 'target_error', 'tool_crash', 'empty_result',
    'valid_negative_result', 'budget_exceeded', 'duplicate_skipped', 'redundant_skipped',
    'scope_denied', 'not_authorized', 'aborted',
  ].includes(declared)) return declared as ToolErrorType;
  const text = `${result.error || ''} ${result.output || ''}`;
  if (result.success) {
    if (!String(result.output || '').trim() && !(result.findings?.length)) return 'empty_result';
    if (!(result.findings?.length) && /(?:no (?:records|findings|vulnerabilities|open ports|interesting paths)|0 open|not found|missing)/i.test(String(result.output || ''))) return 'valid_negative_result';
    return undefined;
  }
  if (/budget exceeded/i.test(text)) return 'budget_exceeded';
  if (/not installed|not found|ENOENT|wordlist|template.*missing/i.test(text)) return 'dependency_missing';
  if (/invalid argument|unknown option|usage:|configuration/i.test(text)) return 'configuration_error';
  if (/429|rate.?limit/i.test(text)) return 'rate_limited';
  if (/403|503|challenge|waf.?block/i.test(text)) return 'waf_blocked';
  if (result.metadata?.aborted === true || /(?:execution|batch|process|tool) aborted/i.test(text)) return 'aborted';
  if (/timed?\s*out|timeout/i.test(text)) return 'timeout';
  if (/ENOTFOUND|EAI_AGAIN|ECONNREFUSED|unreachable|fetch failed|could not resolve/i.test(text)) return 'network_unreachable';
  if (/HTTP\/?\d(?:\.\d)?\s+[45]\d\d|status[: ]+[45]\d\d/i.test(text)) return 'target_error';
  return 'tool_crash';
}

function parseHttp(result: ToolResult): { status?: number; headers?: Record<string, string>; body?: string } {
  const meta = result.metadata || {};
  const status = Number(meta.responseStatus || String(result.output || '').match(/(?:Status:\s*|HTTP\/\S+\s+)(\d{3})/i)?.[1]);
  const headers = meta.responseHeaders && typeof meta.responseHeaders === 'object' ? meta.responseHeaders as Record<string, string> : undefined;
  const body = typeof meta.responseBody === 'string' ? meta.responseBody : undefined;
  return { status: Number.isFinite(status) && status > 0 ? status : undefined, headers, body };
}

function responseFingerprint(status?: number, headers?: Record<string, string>, body?: string): string | undefined {
  if (!status && !headers && body === undefined) return undefined;
  const selectedHeaders = Object.fromEntries(Object.entries(headers || {}).filter(([key]) => /^(?:content-type|server|location|set-cookie|cf-ray|x-amz-cf-id|x-ddos-protection)$/i.test(key)));
  return hash(JSON.stringify(stable({ status, headers: selectedHeaders, bodyHash: body === undefined ? undefined : hash(body) })));
}

function edgeFrom(headers: Record<string, string> = {}, output = ''): { edge: boolean; provider?: string; challenge: boolean } {
  const text = `${JSON.stringify(headers)} ${output}`.toLowerCase();
  const providers: Array<[RegExp, string]> = [
    [/cloudflare|cf-ray|__cf_bm/, 'Cloudflare'], [/ddos-guard|__ddg/, 'DDoS-Guard'],
    [/cloudfront|x-amz-cf/, 'CloudFront'], [/akamai/, 'Akamai'], [/sucuri/, 'Sucuri'],
    [/fastly/, 'Fastly'], [/imperva|incapsula/, 'Imperva'], [/openresty|reverse proxy/, 'Reverse proxy'],
  ];
  const provider = providers.find(([pattern]) => pattern.test(text))?.[1];
  return { edge: !!provider, provider, challenge: /captcha|challenge-platform|checking your browser|access denied|request blocked/.test(text) };
}

export class ToolOrchestrator {
  readonly scanPolicy = new ScanPolicy();
  private readonly records: EvidenceRecord[] = [];
  private readonly events: OrchestratorEvent[] = [];
  private readonly conflicts: EvidenceConflict[] = [];
  private readonly inFlight = new Map<string, Promise<ToolResult>>();
  private readonly admissions = new Map<string, Promise<ToolResult>>();
  private readonly budgets = new Map<string, { limits: TargetBudgets; used: TargetBudgets }>();
  private readonly network = new Map<string, NetworkContext & { recent: Array<{ at: number; type: string; path?: string; fingerprint?: string; category?: string; latencyMs?: number }>; blockedAt?: number; healthChecks: number }>();
  private readonly metrics: OrchestratorMetrics = { actualNetworkRequests: 0, redundantRequestsAvoided: 0, cacheHits: 0, toolFailures: 0, wafEvents: 0, rateLimitEvents: 0, blockedCalls: 0, contradictions: 0, incompleteAreas: [], budgetCostEstimated: 0, budgetCostActual: 0, budgetCostSources: { tool_reported: 0, adapter_measured: 0, orchestrator_estimated: 0 } };
  private readonly wildcardDns = new Map<string, { detected: boolean; addresses: string[]; checkedAt: number }>();
  private readonly hostTails = new Map<string, Promise<void>>();
  private readonly lastHostRequest = new Map<string, number>();
  private readonly dependencyStatus = new Map<string, { available: boolean; path?: string; version?: string; checkedAt: number }>();
  private readonly activeExecutions = new Map<string, { host: string; controller: AbortController; supportsAbort: boolean; toolName: string; parameters: Record<string, unknown> }>();
  private readonly cacheTtlMs: number;
  private readonly preflightTtlMs: number;
  private readonly onEvent?: (event: OrchestratorEvent) => void;
  private readonly dnsResolver: (host: string) => Promise<string[]>;
  private readonly evidenceStore: EvidenceStore;
  private readonly explicitRepeatLimit: number;
  private onCheckpoint?: () => Promise<void>;

  constructor(options: {
    cacheTtlMs?: number;
    budgets?: Partial<TargetBudgets>;
    onEvent?: (event: OrchestratorEvent) => void;
    dnsResolver?: (host: string) => Promise<string[]>;
    preflightTtlMs?: number;
    evidenceStore?: EvidenceStore;
    explicitRepeatLimit?: number;
  } = {}) {
    this.cacheTtlMs = options.cacheTtlMs ?? 15 * 60_000;
    this.defaultBudgets = { ...DEFAULT_BUDGETS, ...(options.budgets || {}) };
    this.onEvent = options.onEvent;
    this.dnsResolver = options.dnsResolver || resolve4;
    this.preflightTtlMs = options.preflightTtlMs ?? Number(process.env.VULNORA_PREFLIGHT_TTL_MS || 5 * 60_000);
    this.evidenceStore = options.evidenceStore || evidenceStoreFromEnvironment();
    this.explicitRepeatLimit = options.explicitRepeatLimit ?? Number(process.env.VULNORA_EXPLICIT_REPEAT_LIMIT || 2);
    void this.evidenceStore.load().catch(() => {});
  }
  private readonly defaultBudgets: TargetBudgets;

  getEvidence(): EvidenceRecord[] { return this.records.map(record => ({ ...record, requestParameters: { ...record.requestParameters } })); }
  getActiveCalls(): { host: string; toolName: string; parameters: unknown }[] {
    return [...this.activeExecutions.values()].map(({ host, toolName, parameters }) => ({ host, toolName, parameters: redactSecrets(redactConfiguredSecrets(parameters)) }));
  }
  getConflicts(): EvidenceConflict[] { return this.conflicts.map(conflict => ({ ...conflict, recordIds: [...conflict.recordIds] })); }
  getEvents(): OrchestratorEvent[] { return this.events.map(event => ({ ...event })); }
  getMetrics(): OrchestratorMetrics { return { ...this.metrics, incompleteAreas: [...this.metrics.incompleteAreas], budgetCostSources: { ...this.metrics.budgetCostSources } }; }
  getBudget(target: string): { limits: TargetBudgets; used: TargetBudgets; remaining: TargetBudgets } {
    const state = this.budgetState(target);
    return { limits: { ...state.limits }, used: { ...state.used }, remaining: Object.fromEntries(Object.keys(state.limits).map(key => [key, Math.max(0, state.limits[key as keyof TargetBudgets] - state.used[key as keyof TargetBudgets])])) as unknown as TargetBudgets };
  }
  getNetworkContext(target: string): NetworkContext {
    const state = this.networkState(target);
    return { edgeSurface: state.edgeSurface, edgeProvider: state.edgeProvider, blockState: state.blockState,
      latencyMs: state.latencyMs, consecutiveTimeouts: state.consecutiveTimeouts, blockingResponses: state.blockingResponses,
      ...(this.scanPolicy.behavior ? { scanning: { behavior: this.scanPolicy.behavior, limits: this.scanPolicy.limits(targetKey(target)) } } : {}) };
  }
  getPreflightStatus(): Record<string, { available: boolean; path?: string; version?: string; checkedAt: number }> {
    return Object.fromEntries([...this.dependencyStatus.entries()].map(([name, value]) => [name, { ...value }]));
  }
  getEvidenceStoreBackend(): EvidenceStore['backend'] { return this.evidenceStore.backend; }
  setCheckpointWriter(writer: () => Promise<void>): void { this.onCheckpoint = writer; }
  private async persistCheckpoint(): Promise<void> {
    try { await this.onCheckpoint?.(); } catch (error) { throw new CheckpointWriteError(error); }
  }

  exportCheckpoint() {
    return structuredClone({ records: this.records, events: this.events, conflicts: this.conflicts,
      budgets: [...this.budgets], network: [...this.network], metrics: this.metrics,
      wildcardDns: [...this.wildcardDns], lastHostRequest: [...this.lastHostRequest], scanPolicy: this.scanPolicy.exportCheckpoint() });
  }

  restoreCheckpoint(state: ReturnType<ToolOrchestrator['exportCheckpoint']>): void {
    if (this.activeExecutions.size || this.inFlight.size || this.admissions.size) throw new Error('Cannot restore over active tool executions.');
    const saved = structuredClone(state);
    if (saved.scanPolicy) this.scanPolicy.restoreCheckpoint(saved.scanPolicy);
    this.records.splice(0, this.records.length, ...saved.records);
    this.events.splice(0, this.events.length, ...saved.events);
    this.conflicts.splice(0, this.conflicts.length, ...saved.conflicts);
    Object.assign(this.metrics, saved.metrics);
    this.budgets.clear(); this.network.clear(); this.wildcardDns.clear(); this.lastHostRequest.clear();
    for (const [key, value] of saved.budgets) this.budgets.set(key, value);
    for (const [key, value] of saved.network) this.network.set(key, value);
    for (const [key, value] of saved.wildcardDns) this.wildcardDns.set(key, value);
    for (const [key, value] of saved.lastHostRequest) this.lastHostRequest.set(key, value);
  }
  refreshPreflight(binary?: string): void { if (binary) this.dependencyStatus.delete(binary); else this.dependencyStatus.clear(); }
  markIncompleteArea(area: string): void {
    if (!this.metrics.incompleteAreas.includes(area)) this.metrics.incompleteAreas.push(area);
  }

  abortTarget(target: string, reason = 'manual abort'): number {
    const host = targetKey(target);
    let aborted = 0;
    for (const active of this.activeExecutions.values()) {
      if (active.host === host && active.supportsAbort && !active.controller.signal.aborted) {
        active.controller.abort(new Error(reason));
        aborted++;
      }
    }
    return aborted;
  }

  /** Record a denial made by the immutable outer ScopeGuard/approval gates. */
  recordBlocked(tool: CustomTool, context: ToolContext, result: ToolResult, reason: 'scope_denied' | 'not_authorized'): void {
    const call = normalizeToolCall(tool.name, context);
    this.metrics.blockedCalls++;
    this.emit('BLOCKED', reason.replace(/_/g, ' '), call);
    this.store(call, context, result, 0, reason);
    this.abortTarget(call.host, reason);
  }

  private emit(action: OrchestratorEvent['action'], reason: string, call: NormalizedToolCall): void {
    const event = { action, reason, toolName: call.toolName, target: call.normalizedTarget, signature: call.normalizedSignature, timestamp: Date.now() };
    this.events.push(event); this.onEvent?.(event);
  }
  private budgetState(target: string): { limits: TargetBudgets; used: TargetBudgets } {
    const key = targetKey(target);
    let state = this.budgets.get(key);
    if (!state) { state = { limits: { ...this.defaultBudgets }, used: Object.fromEntries(Object.keys(this.defaultBudgets).map(name => [name, 0])) as unknown as TargetBudgets }; this.budgets.set(key, state); }
    return state;
  }
  private networkState(target: string) {
    const key = targetKey(target);
    let state = this.network.get(key);
    if (!state) { state = { edgeSurface: false, blockState: 'clear' as const, consecutiveTimeouts: 0, blockingResponses: 0, recent: [], healthChecks: 0 }; this.network.set(key, state); }
    return state;
  }

  private budgetKey(category: OrchestratedToolCategory): keyof TargetBudgets | null {
    if (category === 'dns' || category === 'passive_recon' || category === 'port_discovery' || category === 'service_detection' || category === 'full_port_scan' || category === 'tls') return 'passive_recon_budget';
    if (category === 'http_fetch' || category === 'http_analysis') return 'baseline_http_budget';
    if (category === 'content_discovery') return 'content_discovery_budget';
    if (category === 'active_validation') return 'active_validation_budget';
    if (category === 'exploit_validation') return 'exploit_validation_budget';
    return null;
  }

  private preciseBudgetKey(call: NormalizedToolCall): keyof TargetBudgets {
    if (['port_discovery', 'service_detection', 'full_port_scan'].includes(call.toolCategory)) return 'port_probe_budget';
    if (call.toolCategory === 'http_fetch') return 'http_request_budget';
    if (call.toolCategory === 'content_discovery' || /(?:nuclei|katana|ffuf|gobuster|ferox|nikto|testssl)/i.test(call.toolName)) return 'batch_tool_budget';
    return 'tool_call_budget';
  }

  private estimatedRequests(call: NormalizedToolCall): number {
    if (call.toolCategory === 'offline' || call.toolCategory === 'reporting' || call.toolCategory === 'http_analysis') return 0;
    if (call.toolName === 'dir_bruteforce') return /extended/i.test(String(call.relevantParameters.wordlist || '')) ? 60 : 17;
    if (call.toolName === 'api_endpoint_discovery') return 42;
    if (/(?:subdomain_enum|subfinder|amass)/i.test(call.toolName)) return /extended/i.test(String(call.relevantParameters.wordlist || '')) ? 62 : 22;
    if (/^(?:xss_scan|sqli_scan)$/.test(call.toolName)) return call.toolName === 'xss_scan' ? 6 : 8;
    if (call.toolCategory === 'port_discovery' || call.toolCategory === 'service_detection' || call.toolCategory === 'full_port_scan') return Math.max(1, portSet(call.relevantParameters.ports).length || (call.toolCategory === 'full_port_scan' ? 65535 : 1000));
    return 1;
  }

  private reserveBudget(call: NormalizedToolCall, cost: number, additionalRequest = false): { failure: ToolResult | null; key: keyof TargetBudgets; estimated: number } {
    const preciseKey = this.preciseBudgetKey(call);
    if (cost <= 0) return { failure: null, key: preciseKey, estimated: 0 };
    const state = this.budgetState(call.host);
    const key = this.budgetKey(call.toolCategory);
    const toolCost = additionalRequest ? 0 : 1;
    const preciseCost = preciseKey === 'batch_tool_budget' || preciseKey === 'tool_call_budget' ? toolCost : cost;
    if (state.used.total_request_budget + cost > state.limits.total_request_budget
      || state.used.tool_call_budget + toolCost > state.limits.tool_call_budget
      || state.used[preciseKey] + preciseCost > state.limits[preciseKey]
      || (key && state.used[key] + cost > state.limits[key])) {
      this.metrics.blockedCalls++;
      this.emit('BLOCKED', 'budget exceeded', call);
      return { failure: { success: false, error: 'ORCHESTRATOR budget_exceeded: target request budget exhausted.', metadata: { orchestrationStatus: 'budget_exceeded', networkRequests: 0 } }, key: preciseKey, estimated: cost };
    }
    state.used.total_request_budget += cost;
    state.used.tool_call_budget += toolCost;
    if (preciseKey !== 'tool_call_budget') state.used[preciseKey] += preciseCost;
    if (key) state.used[key] += cost;
    this.metrics.actualNetworkRequests += cost;
    this.metrics.budgetCostEstimated += cost;
    return { failure: null, key: preciseKey, estimated: cost };
  }

  private reconcileBudget(call: NormalizedToolCall, reservation: { key: keyof TargetBudgets; estimated: number }, result: ToolResult): { actual?: number; source: EvidenceRecord['budgetCostSource'] } {
    const metadata = result.metadata || {};
    const reported = [metadata.networkRequestsActual, metadata.actualRequests, metadata.requestCount]
      .map(Number).find(value => Number.isFinite(value) && value >= 0);
    if (reported === undefined) {
      this.metrics.budgetCostActual += reservation.estimated;
      this.metrics.budgetCostSources.orchestrator_estimated++;
      return { source: 'orchestrator_estimated' };
    }
    const actual = Math.round(reported);
    const delta = actual - reservation.estimated;
    const state = this.budgetState(call.host);
    state.used.total_request_budget = Math.max(0, state.used.total_request_budget + delta);
    if (reservation.key === 'http_request_budget' || reservation.key === 'port_probe_budget') {
      state.used[reservation.key] = Math.max(0, state.used[reservation.key] + delta);
    }
    const legacyKey = this.budgetKey(call.toolCategory);
    if (legacyKey) state.used[legacyKey] = Math.max(0, state.used[legacyKey] + delta);
    this.metrics.actualNetworkRequests = Math.max(0, this.metrics.actualNetworkRequests + delta);
    const source = metadata.networkRequestsActual !== undefined ? 'adapter_measured' : 'tool_reported';
    this.metrics.budgetCostActual += actual;
    this.metrics.budgetCostSources[source]++;
    return { actual, source };
  }

  private cached(call: NormalizedToolCall): EvidenceRecord | undefined {
    const now = Date.now();
    return [...this.records].reverse().find(record => record.equivalentSignature === call.equivalentSignature && record.status === 'success' && now - record.timestamp <= this.cacheTtlMs);
  }

  private priorPortEvidence(call: NormalizedToolCall): EvidenceRecord[] {
    return this.records.filter(record => ['port_discovery', 'service_detection', 'full_port_scan', 'http_fetch', 'tls'].includes(record.toolCategory)
      && record.status === 'success'
      && normalizeToolCall(record.toolName, { parameters: record.requestParameters }).host === call.host);
  }

  getOpenPorts(target: string): number[] {
    const call = normalizeToolCall('nmap_scan', { parameters: { target } });
    return [...new Set(this.priorPortEvidence(call).flatMap(record => {
      const ports = [...record.rawOutput.matchAll(/(\d+)\/tcp\s+open/g)].map(match => Number(match[1]));
      if (record.toolCategory === 'http_fetch') {
        const normalized = normalizeToolCall(record.toolName, { parameters: record.requestParameters });
        if (normalized.port) ports.push(normalized.port);
      }
      if (record.toolCategory === 'tls') {
        const normalized = normalizeToolCall(record.toolName, { parameters: record.requestParameters });
        ports.push(normalized.port || 443);
      }
      return ports;
    }))];
  }

  private portStageGate(call: NormalizedToolCall, context: ToolContext): ToolResult | null {
    if (!['service_detection', 'full_port_scan'].includes(call.toolCategory)) return null;
    const prior = this.priorPortEvidence(call);
    const discoveredOpen = new Set(this.getOpenPorts(call.host));
    if (call.toolCategory === 'service_detection') {
      if (!discoveredOpen.size) return { success: false, error: 'ORCHESTRATOR configuration_error: service detection requires prior open-port evidence.', metadata: { orchestrationStatus: 'configuration_error', requiredCapability: 'port_discovery', missingEvidence: 'confirmed or strongly evidenced open ports', recommendedNextAction: 'schedule a smaller port-discovery fallback', retryAfterCapability: 'port_discovery' } };
      const requested = portSet(context.parameters.ports);
      const scoped = requested.length ? requested.filter(port => discoveredOpen.has(port)) : [...discoveredOpen];
      if (!scoped.length) return { success: false, error: 'ORCHESTRATOR redundant_skipped: requested service ports were not observed open.', metadata: { orchestrationStatus: 'redundant_skipped' } };
      context.parameters.ports = scoped.join(',');
    }
    if (call.toolCategory === 'full_port_scan') {
      if (!context.authorizationReceipt) return { success: false, error: 'ORCHESTRATOR configuration_error: full port scan requires an authorization receipt.', metadata: { orchestrationStatus: 'configuration_error' } };
      if (!prior.some(record => record.toolCategory === 'port_discovery')) return { success: false, error: 'ORCHESTRATOR configuration_error: full port scan requires a completed standard-port discovery stage.', metadata: { orchestrationStatus: 'configuration_error' } };
      if (this.networkState(call.host).blockState === 'probable_edge_block') return { success: false, error: 'ORCHESTRATOR waf_blocked: full port scan disabled during a probable edge block.', metadata: { orchestrationStatus: 'waf_blocked' } };
      context.parameters.expected_gain = context.parameters.expected_gain || 'Complete remaining port coverage after staged discovery; no prior full scan exists.';
    }
    return null;
  }

  private async detectWildcard(domain: string): Promise<{ detected: boolean; addresses: string[]; checkedAt: number }> {
    const existing = this.wildcardDns.get(domain);
    if (existing && Date.now() - existing.checkedAt <= this.cacheTtlMs) return existing;
    const random = `vulnora-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}.${domain}`;
    let addresses: string[] = [];
    try { addresses = await this.dnsResolver(random); } catch { /* NXDOMAIN means no wildcard */ }
    const state = { detected: addresses.length > 0, addresses: [...new Set(addresses)].sort(), checkedAt: Date.now() };
    this.wildcardDns.set(domain, state);
    return state;
  }

  private async runWithNetworkPolicy(call: NormalizedToolCall, runner: () => Promise<ToolResult>): Promise<ToolResult> {
    if (this.scanPolicy.behavior) return runner();
    const networked = !['offline', 'reporting', 'http_analysis'].includes(call.toolCategory);
    const state = this.networkState(call.host);
    if (!networked || state.blockState === 'clear') return runner();
    const previous = this.hostTails.get(call.host) || Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const tail = previous.catch(() => {}).then(() => gate);
    this.hostTails.set(call.host, tail);
    await previous.catch(() => {});
    try {
      const configuredDelay = Number(process.env.VULNORA_DEFENSIVE_REQUEST_INTERVAL_MS || 750);
      const baseDelay = AGGRESSIVE_TOOLS.test(call.toolName) ? configuredDelay * 2 : configuredDelay;
      const jitter = Number(process.env.VULNORA_DEFENSIVE_JITTER_MS || 500);
      const wait = Math.max(0, baseDelay - (Date.now() - (this.lastHostRequest.get(call.host) || 0))) + Math.floor(Math.random() * Math.max(1, jitter));
      if (wait > 0) await new Promise(resolve => setTimeout(resolve, wait));
      this.lastHostRequest.set(call.host, Date.now());
      return await runner();
    } finally {
      release();
      if (this.hostTails.get(call.host) === tail) this.hostTails.delete(call.host);
    }
  }

  private baseline(call: NormalizedToolCall): EvidenceRecord | undefined {
    return [...this.records].reverse().find(record => record.toolCategory === 'http_fetch' && record.status === 'success' && record.target === call.normalizedTarget && Date.now() - record.timestamp <= this.cacheTtlMs);
  }

  private offlineAnalysis(toolName: string, baseline: EvidenceRecord): ToolResult | undefined {
    const headers = baseline.responseHeaders || {};
    const url = baseline.target;
    if (toolName === 'header_analysis') {
      const required = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];
      return { success: true, output: `Security Header Analysis for ${url} (cached response):\n${required.map(name => `${name}: ${headers[name] ? `✓ ${headers[name]}` : '✗ Missing'}`).join('\n')}`, metadata: { cacheHit: true, offlineAnalysis: true } };
    }
    if (toolName === 'cookie_analysis') {
      const cookies = headers['set-cookie'];
      return { success: true, output: cookies ? `Cookie Analysis for ${url} (cached response):\n${cookies}` : `Cookie Analysis for ${url} (cached response):\nNo Set-Cookie headers found in the response.`, metadata: { cacheHit: true, offlineAnalysis: true } };
    }
    if (toolName === 'csp_analysis') {
      const csp = headers['content-security-policy'] || headers['content-security-policy-report-only'];
      return { success: true, output: csp ? `CSP Analysis for ${url} (cached response):\n${csp}` : `CSP Analysis for ${url} (cached response):\nNo Content-Security-Policy header found.`, metadata: { cacheHit: true, offlineAnalysis: true } };
    }
    if (toolName === 'clickjacking_test') {
      return { success: true, output: `Clickjacking Protection Test for ${url} (cached response):\nX-Frame-Options: ${headers['x-frame-options'] || 'Missing'}\nCSP frame-ancestors: ${headers['content-security-policy']?.includes('frame-ancestors') ? 'Present' : 'Missing'}`, metadata: { cacheHit: true, offlineAnalysis: true } };
    }
    if (toolName === 'technology_detect') {
      const technologies = [headers.server, headers['x-powered-by'], headers['cf-ray'] ? 'Cloudflare' : '', headers['x-amz-cf-id'] ? 'CloudFront' : ''].filter(Boolean);
      return { success: true, output: `Technology detection for ${url} (cached response):\n${technologies.length ? technologies.join(', ') : 'No header-level technologies detected.'}`, metadata: { cacheHit: true, offlineAnalysis: true } };
    }
    return undefined;
  }

  private async preflight(tool: CustomTool, call: NormalizedToolCall): Promise<ToolResult | null> {
    // Configuration errors are more actionable than a secondary missing-binary
    // error, so validate requested input files before checking the executable.
    const requestedFiles = [
      ['wordlist', call.relevantParameters.wordlist || call.toolConfiguration.wordlist],
      ['templates', call.relevantParameters.templates || call.toolConfiguration.templates],
      ['config', call.relevantParameters.config_file || call.toolConfiguration.config_file],
    ] as Array<[string, unknown]>;
    for (const [label, rawPath] of requestedFiles) {
      const path = typeof rawPath === 'string' ? rawPath.trim() : '';
      if (path && (path.includes('/') || /\.(?:txt|ya?ml|json|toml)$/i.test(path))) {
        try {
          const details = await stat(path);
          const valid = label === 'templates' ? details.isFile() || details.isDirectory() : details.isFile();
          if (!valid) throw new Error(`${label} has the wrong filesystem type`);
        } catch {
          return { success: false, error: `ORCHESTRATOR configuration_error: ${label} file not found: ${path}`, metadata: { orchestrationStatus: 'configuration_error' } };
        }
      }
    }
    for (const key of ['timeout', 'max_time']) {
      const raw = call.toolConfiguration[key];
      if (raw !== undefined && (!Number.isFinite(Number(raw)) || Number(raw) <= 0)) {
        return { success: false, error: `ORCHESTRATOR configuration_error: ${key} must be a positive number.`, metadata: { orchestrationStatus: 'configuration_error' } };
      }
    }
    const binary = tool.binary || TOOL_BINARIES[tool.name];
    if (binary) {
      let dependency = this.dependencyStatus.get(binary);
      if (dependency && Date.now() - dependency.checkedAt > this.preflightTtlMs) {
        this.dependencyStatus.delete(binary);
        dependency = undefined;
      }
      if (!dependency) {
        const executablePath = await commandPath(binary);
        dependency = { available: !!executablePath, path: executablePath, checkedAt: Date.now() };
        if (executablePath) {
          try {
            const version = await execFileAsync(executablePath, VERSION_ARGS[binary] || ['--version'], { timeout: 5_000, maxBuffer: 256 * 1024 });
            dependency.version = String(version.stdout || version.stderr || '').split(/\r?\n/).find(Boolean)?.trim() || 'available';
          } catch { dependency.version = 'available (version probe unsupported)'; }
        }
        this.dependencyStatus.set(binary, dependency);
      }
      if (!dependency.available) return { success: false, error: `ORCHESTRATOR dependency_missing: ${binary} is not executable on PATH.`, metadata: { orchestrationStatus: 'dependency_missing' } };
    }
    try {
      const disk = await statfs(process.cwd());
      if (disk.bavail * disk.bsize < 10 * 1024 * 1024) return { success: false, error: 'ORCHESTRATOR configuration_error: less than 10 MiB free disk space.', metadata: { orchestrationStatus: 'configuration_error' } };
    } catch { /* platforms without statfs remain supported */ }
    return null;
  }

  private blockedByEdge(call: NormalizedToolCall): ToolResult | null {
    const state = this.networkState(call.host);
    if (state.blockState !== 'probable_edge_block') return null;
    const backoffMs = Number(process.env.VULNORA_EDGE_BACKOFF_MS || 60_000);
    const healthCheck = call.toolCategory === 'http_fetch' && ['GET', 'HEAD'].includes(call.method || 'GET') && Date.now() - (state.blockedAt || 0) >= backoffMs && state.healthChecks < 1;
    if (healthCheck) { state.healthChecks++; this.emit('REPEATED', 'controlled health check after edge backoff', call); return null; }
    this.metrics.blockedCalls++;
    this.metrics.redundantRequestsAvoided++;
    this.emit('STOPPED', 'probable WAF block', call);
    return { success: false, error: 'ORCHESTRATOR waf_blocked: probable edge block; alternative-tool retries are disabled.', metadata: { orchestrationStatus: 'waf_blocked', networkRequests: 0 } };
  }

  private fullScanOverlap(call: NormalizedToolCall): EvidenceRecord | undefined {
    if (!['port_discovery', 'service_detection'].includes(call.toolCategory)) return undefined;
    return [...this.records].reverse().find(record => record.toolCategory === 'full_port_scan' && record.status === 'success' && normalizeToolCall(record.toolName, { parameters: record.requestParameters }).host === call.host);
  }

  async execute(tool: CustomTool, context: ToolContext, runner: () => Promise<ToolResult>): Promise<ToolResult> {
    if (context.purpose === 'reporting' || context.repeatReason) return this.executeAdmitted(tool, context, runner);
    const call = normalizeToolCall(tool.name, context);
    const pending = this.admissions.get(call.normalizedSignature);
    if (pending) {
      this.metrics.cacheHits++; this.metrics.redundantRequestsAvoided++;
      this.emit('USED', 'in-flight shared evidence', call);
      const result = await pending;
      const shared = { ...result, metadata: { ...result.metadata, cacheHit: true, orchestrationStatus: 'duplicate_skipped', networkRequests: 0 } };
      this.store(call, context, shared, 0, 'duplicate_skipped');
      return shared;
    }
    // Claim the request before asynchronous preflight or wordlist preparation.
    const execution = this.executeAdmitted(tool, context, runner);
    this.admissions.set(call.normalizedSignature, execution);
    try { return await execution; } finally { this.admissions.delete(call.normalizedSignature); }
  }

  private async executeAdmitted(tool: CustomTool, context: ToolContext, runner: () => Promise<ToolResult>): Promise<ToolResult> {
    let call = normalizeToolCall(tool.name, context);
    if (context.purpose === 'reporting' && toolCategory(tool.name, context.parameters) !== 'offline') {
      this.metrics.blockedCalls++; this.emit('BLOCKED', 'reporting is evidence-store only', call);
      const result: ToolResult = { success: false, error: 'ORCHESTRATOR redundant_skipped: reporting cannot execute new scan tools.', metadata: { orchestrationStatus: 'redundant_skipped', networkRequests: 0 } };
      this.store(call, context, result, 0, 'redundant_skipped');
      return result;
    }
    const preflight = await this.preflight(tool, call);
    if (preflight) { this.metrics.toolFailures++; this.emit('FAILED', errorType(preflight) || 'configuration error', call); this.store(call, context, preflight, 0); return preflight; }
    const edgeBlocked = this.blockedByEdge(call);
    if (edgeBlocked) { this.store(call, context, edgeBlocked, 0); return edgeBlocked; }
    const portGate = this.portStageGate(call, context);
    if (portGate) {
      this.metrics.blockedCalls++;
      this.emit(portGate.metadata?.orchestrationStatus === 'redundant_skipped' ? 'SKIPPED' : 'BLOCKED', String(portGate.metadata?.orchestrationStatus || 'port stage gate'), call);
      this.store(call, context, portGate, 0, errorType(portGate));
      return portGate;
    }
    // Service-stage gating may narrow the requested set to ports already observed
    // open. Persist/cache the call that will actually run, not the broader LLM plan.
    if (['service_detection', 'full_port_scan'].includes(call.toolCategory)) {
      call = normalizeToolCall(tool.name, context);
    }
    const overlap = this.fullScanOverlap(call);
    if (overlap) {
      this.metrics.redundantRequestsAvoided++; this.emit('SKIPPED', 'equivalent full-port evidence already covers this scan', call);
      const result = { ...overlap.result, metadata: { ...(overlap.result.metadata || {}), orchestrationStatus: 'redundant_skipped', cacheHit: true, networkRequests: 0 } };
      this.store(call, context, result, 0, 'redundant_skipped'); return result;
    }
    if (call.toolCategory === 'http_analysis') {
      const base = this.baseline(call);
      const offline = base && this.offlineAnalysis(tool.name, base);
      if (offline) { this.metrics.cacheHits++; this.metrics.redundantRequestsAvoided++; this.emit('USED', 'cached evidence', call); this.store(call, context, offline, 0); return offline; }
    }
    const latestEquivalent = [...this.records].reverse().find(record => record.equivalentSignature === call.equivalentSignature);
    const technicalErrors = new Set<ToolErrorType>(['timeout', 'network_unreachable', 'waf_blocked', 'rate_limited', 'target_error', 'tool_crash']);
    const recentEquivalent = this.records.filter(record => record.equivalentSignature === call.equivalentSignature && Date.now() - record.timestamp <= this.cacheTtlMs);
    const sinceLastSuccess = (() => {
      const lastSuccess = recentEquivalent.map(record => record.status).lastIndexOf('success');
      return recentEquivalent.slice(lastSuccess + 1);
    })();
    const consecutiveFailures = [...sinceLastSuccess].reverse().findIndex(record => record.status !== 'failed' || !record.errorType || !technicalErrors.has(record.errorType));
    const technicalFailureCount = consecutiveFailures === -1 ? sinceLastSuccess.length : consecutiveFailures;
    const allowedExplicitReasons = new Set<RepeatReason>(['contradiction_verification', 'independent_confirmation_required', 'different_network_perspective', 'materially_different_configuration']);
    const explicitRepeatCount = recentEquivalent.filter(record => record.repeatReason && allowedExplicitReasons.has(record.repeatReason)).length;
    const validExplicitRepeat = !!context.repeatReason && allowedExplicitReasons.has(context.repeatReason) && explicitRepeatCount < this.explicitRepeatLimit;
    if (latestEquivalent?.status === 'failed' && technicalFailureCount >= 2 && !validExplicitRepeat) {
      this.metrics.redundantRequestsAvoided++;
      this.metrics.blockedCalls++;
      this.emit('SKIPPED', 'repeated failure limit reached', call);
      const result: ToolResult = {
        success: false,
        error: 'ORCHESTRATOR redundant_skipped: two equivalent attempts failed without new evidence.',
        metadata: { orchestrationStatus: 'redundant_skipped', cacheHit: true, networkRequests: 0 },
      };
      this.store(call, context, result, 0, 'redundant_skipped');
      return result;
    }
    const inferredRepeatReason: RepeatReason | undefined = context.repeatReason
      || (latestEquivalent?.status === 'failed' ? 'previous_failure' : undefined)
      || (latestEquivalent?.status === 'success' && Date.now() - latestEquivalent.timestamp > this.cacheTtlMs ? 'expired_cache' : undefined);
    const cached = inferredRepeatReason ? undefined : this.cached(call);
    if (cached) {
      this.metrics.cacheHits++; this.metrics.redundantRequestsAvoided++;
      const duplicate = cached.normalizedSignature === call.normalizedSignature;
      this.emit('SKIPPED', duplicate ? 'duplicate' : 'equivalent', call);
      const result = { ...cached.result, metadata: { ...(cached.result.metadata || {}), orchestrationStatus: duplicate ? 'duplicate_skipped' : 'redundant_skipped', cacheHit: true, networkRequests: 0 } };
      this.store(call, context, result, 0, duplicate ? 'duplicate_skipped' : 'redundant_skipped'); return result;
    }
    const pending = this.inFlight.get(call.equivalentSignature);
    if (pending) {
      this.metrics.cacheHits++; this.metrics.redundantRequestsAvoided++; this.emit('USED', 'in-flight shared evidence', call);
      const result = await pending;
      const shared = { ...result, metadata: { ...(result.metadata || {}), orchestrationStatus: 'duplicate_skipped', cacheHit: true, networkRequests: 0 } };
      this.store(call, context, shared, 0, 'duplicate_skipped');
      return shared;
    }
    let cost = this.estimatedRequests(call);
    if (/^(?:ffuf_fuzz|ffuf_tool|gobuster_tool|feroxbuster_tool)$/.test(tool.name)) {
      const source = typeof context.parameters.wordlist === 'string' && context.parameters.wordlist.trim() && context.parameters.wordlist !== 'common'
        ? context.parameters.wordlist : DEFAULT_WEB_WORDLIST;
      try {
        const words = [...new Set((await readFile(source, 'utf8')).split(/\r?\n/).map(word => word.trim()).filter(word => word && !word.startsWith('#')))];
        const remaining = this.getBudget(call.host).remaining;
        const overhead = /ffuf/.test(tool.name) ? 0 : 10;
        const limit = Math.max(0, Math.min(remaining.total_request_budget, remaining.content_discovery_budget) - overhead);
        const entries = words.slice(0, limit);
        cost = Math.max(1, entries.length) + overhead;
        context.preparedWordlist = { source, entries, totalEntries: words.length, reservedRequests: cost };
      } catch {
        const result: ToolResult = { success: false, error: `ORCHESTRATOR configuration_error: discovery wordlist cannot be read: ${source}`, metadata: { orchestrationStatus: 'configuration_error', networkRequests: 0 } };
        this.store(call, context, result, 0); return result;
      }
    }
    const reservation = this.reserveBudget(call, cost);
    if (reservation.failure) { this.store(call, context, reservation.failure, 0, 'budget_exceeded', reservation.estimated); return reservation.failure; }
    // Retain charged budgets even if the process dies during the network operation.
    await this.persistCheckpoint();
    const started = Date.now();
    const controller = new AbortController();
    context.abortSignal = context.abortSignal ? AbortSignal.any([controller.signal, context.abortSignal]) : controller.signal;
    context.abortSignal.throwIfAborted();
    let httpRequests = 0;
    let httpCheckpointError: CheckpointWriteError | undefined;
    if (this.scanPolicy.behavior) context.beforeHttpRequest = async () => {
      if (httpCheckpointError) { throw httpCheckpointError; }
      if (httpRequests >= reservation.estimated) {
        const extra = this.reserveBudget(call, 1, true);
        if (extra.failure) throw new Error(extra.failure.error);
        reservation.estimated++;
      }
      try { await this.persistCheckpoint(); }
      catch (error) { httpCheckpointError = error as CheckpointWriteError; throw error; }
      context.abortSignal?.throwIfAborted();
      httpRequests++;
    };
    this.activeExecutions.set(call.normalizedSignature, { host: call.host, controller, supportsAbort: tool.supportsAbort === true, toolName: tool.name, parameters: { ...context.parameters } });
    const execution = (async () => {
      try {
        const wildcard = /(?:subdomain_enum|subfinder|amass)/i.test(tool.name) ? await this.detectWildcard(call.host) : undefined;
        context.abortSignal?.throwIfAborted();
        const raw = await this.runWithNetworkPolicy(call, runner);
        if (httpCheckpointError) throw httpCheckpointError;
        if (httpRequests) raw.metadata = { ...(raw.metadata || {}), networkRequestsActual: httpRequests };
        if (context.abortSignal?.aborted) return { ...raw, success: false, error: `Execution aborted: ${String(context.abortSignal.reason || 'policy stop')}`, metadata: { ...(raw.metadata || {}), aborted: true } };
        if (wildcard?.detected) {
          return {
            ...raw,
            output: `${raw.output || ''}\n\nWildcard DNS detected (${wildcard.addresses.join(', ')}). DNS-only candidates are unverified and catch-all responses are not counted as separate applications.`,
            findings: (raw.findings || []).filter(finding => !/subdomains discovered/i.test(finding.title)),
            metadata: { ...(raw.metadata || {}), wildcardDns: true, wildcardAddresses: wildcard.addresses, candidatesVerified: false },
          };
        }
        return raw;
      } catch (error) {
        if (httpCheckpointError) throw httpCheckpointError;
        if (error instanceof CheckpointWriteError) throw error;
        return { success: false, error: error instanceof Error ? error.message : String(error), metadata: {
          ...(httpRequests ? { networkRequestsActual: httpRequests } : {}), ...(context.abortSignal?.aborted ? { aborted: true } : {}),
        } };
      }
    })();
    this.inFlight.set(call.equivalentSignature, execution);
    try {
      const result = await execution;
      const duration = Date.now() - started;
      if (this.scanPolicy.behavior && !httpRequests && cost > 0) {
        this.scanPolicy.observe(call.host, 0, result.success ? Number(result.metadata?.responseStatus || 200) : undefined);
      }
      const reconciled = this.reconcileBudget(call, reservation, result);
      const record = this.store(call, context, result, duration, undefined, reservation.estimated, reconciled.actual, reconciled.source);
      if (inferredRepeatReason) {
        record.repeatReason = inferredRepeatReason;
        const reason = inferredRepeatReason === 'materially_different_configuration'
          ? 'fallback strategy: materially different configuration'
          : inferredRepeatReason.replace(/_/g, ' ');
        this.emit('REPEATED', reason, call);
      }
      this.updateNetwork(record, duration, result, call);
      this.resolveConflicts(record);
      if (!result.success) { this.metrics.toolFailures++; this.emit('FAILED', record.errorType || 'tool error', call); }
      else this.emit('EXECUTED', 'new evidence', call);
      await this.persistCheckpoint();
      return { ...record.result, metadata: { ...(record.result.metadata || {}), orchestrationStatus: record.errorType || 'executed', executionStatus: record.executionStatus, resultType: record.resultType, networkRequests: reconciled.actual ?? cost, evidenceRecordId: record.id, budgetCostEstimated: reservation.estimated, budgetCostActual: reconciled.actual, budgetCostSource: reconciled.source } };
    } finally {
      this.inFlight.delete(call.equivalentSignature);
      this.activeExecutions.delete(call.normalizedSignature);
    }
  }

  private store(
    call: NormalizedToolCall,
    context: ToolContext,
    result: ToolResult,
    latencyMs: number,
    forcedError?: ToolErrorType,
    budgetCostEstimated = 0,
    budgetCostActual?: number,
    budgetCostSource: EvidenceRecord['budgetCostSource'] = 'orchestrator_estimated'
  ): EvidenceRecord {
    const http = parseHttp(result); const fingerprint = responseFingerprint(http.status, http.headers, http.body);
    const edge = edgeFrom(http.headers, `${result.output || ''} ${http.body || ''}`);
    const network = this.networkState(call.host);
    const classified = forcedError || errorType(result);
    const id = `evidence-${this.records.length + 1}`;
    const enrichedFindings = (result.findings || []).map((finding, index) => ({
      ...finding,
      findingId: finding.findingId || `${id}:finding:${index + 1}`,
      evidenceRecordIds: [...new Set([...(finding.evidenceRecordIds || []), id])],
      attemptId: finding.attemptId || context.attemptId,
      sourceToolCallId: finding.sourceToolCallId || context.sourceToolCallId,
    }));
    const enrichedResult: ToolResult = { ...result, findings: enrichedFindings.length ? enrichedFindings : result.findings };
    const policyReason: PolicyReason | undefined = classified === 'scope_denied' ? 'scope_denied'
      : classified === 'not_authorized' ? 'not_authorized'
        : classified === 'budget_exceeded' ? 'budget_exceeded'
          : context.purpose === 'reporting' && classified === 'redundant_skipped' ? 'reporting_only' : undefined;
    const executionStatus: ExecutionStatus = classified === 'duplicate_skipped' || classified === 'redundant_skipped' || classified === 'scope_denied' || classified === 'not_authorized'
      ? 'skipped' : classified === 'waf_blocked' || classified === 'rate_limited' || classified === 'aborted' ? 'deferred' : classified === 'budget_exceeded' ? 'blocked' : result.success ? 'executed' : 'failed';
    const resultType: ResultType = classified === 'aborted' ? 'inconclusive' : !result.success ? 'error' : classified === 'empty_result' ? 'empty' : classified === 'valid_negative_result' ? 'negative' : enrichedFindings.length ? 'positive' : 'inconclusive';
    const record: EvidenceRecord = {
      id, toolName: call.toolName, toolCategory: call.toolCategory,
      normalizedSignature: call.normalizedSignature, equivalentSignature: call.equivalentSignature,
      target: call.normalizedTarget, timestamp: Date.now(), requestParameters: { ...context.parameters },
      rawOutput: String(result.output || result.error || ''), parsedOutput: result.metadata,
      status: classified === 'duplicate_skipped' || classified === 'redundant_skipped' || classified === 'scope_denied' || classified === 'not_authorized'
        ? 'skipped'
        : classified === 'waf_blocked' || classified === 'rate_limited' || classified === 'aborted'
          ? 'deferred'
          : result.success ? 'success' : 'failed',
      confidence: result.success ? 0.85 : 0.35, sourceAgent: context.operator || 'unknown',
      responseStatus: http.status, responseHeaders: http.headers,
      responseBodyHash: http.body === undefined ? undefined : hash(http.body), responseFingerprint: fingerprint,
      networkContext: { edgeSurface: edge.edge || network.edgeSurface, edgeProvider: edge.provider || network.edgeProvider, blockState: network.blockState, latencyMs, consecutiveTimeouts: network.consecutiveTimeouts, blockingResponses: network.blockingResponses },
      errorType: classified, result: enrichedResult,
      executionStatus, resultType, policyReason,
      attemptId: context.attemptId, sourceToolCallId: context.sourceToolCallId,
      findingIds: enrichedFindings.map(finding => finding.findingId!),
      budgetCostEstimated, budgetCostActual, budgetCostSource,
    };
    // Compute policy and hashes from the original response; retain only redacted evidence.
    const scrub = <T>(value: T): T => redactSecrets(redactConfiguredSecrets(value)) as T;
    record.target = scrub(record.target);
    record.requestParameters = scrub(record.requestParameters);
    record.rawOutput = scrub(record.rawOutput);
    record.parsedOutput = scrub(record.parsedOutput);
    record.responseHeaders = scrub(record.responseHeaders);
    record.result = scrub(record.result);
    this.records.push(record);
    void this.evidenceStore.append(record).catch(() => {});
    return record;
  }

  private updateNetwork(record: EvidenceRecord, latencyMs: number, raw: ToolResult, call: NormalizedToolCall): void {
    const http = parseHttp(raw);
    const state = this.networkState(call.host); const now = Date.now();
    const edge = edgeFrom(http.headers, `${raw.output || ''} ${http.body || ''}`);
    if (edge.edge) { state.edgeSurface = true; state.edgeProvider = edge.provider; if (state.blockState === 'clear') state.blockState = 'defensive'; }
    state.latencyMs = state.latencyMs === undefined ? latencyMs : Math.round(state.latencyMs * 0.7 + latencyMs * 0.3);
    const priorRouteSuccess = state.recent.some(item => item.path === call.path && item.type === 'success');
    const repeatedBlockFingerprint = !!record.responseFingerprint && state.recent.some(item => item.fingerprint === record.responseFingerprint && item.path !== call.path && /^403_/.test(item.type));
    const wafCookie = /(?:__cf_bm|cf_clearance|__ddg|incap_ses|visid_incap|sucuri)/i.test(String(http.headers?.['set-cookie'] || ''));
    const latencyShift = state.latencyMs !== undefined && latencyMs > Math.max(1500, state.latencyMs * 3);
    const providerSignal = edge.edge || !!record.networkContext.edgeProvider;
    const strong403 = record.responseStatus === 403 && (edge.challenge || wafCookie || repeatedBlockFingerprint || priorRouteSuccess || latencyShift || providerSignal);
    const strong503 = record.responseStatus === 503 && (edge.challenge || providerSignal || wafCookie);
    const type = record.errorType === 'timeout' || record.errorType === 'network_unreachable' ? 'timeout'
      : record.responseStatus === 429 ? '429'
        : strong403 ? '403_strong'
          : record.responseStatus === 403 ? '403_weak'
            : strong503 ? '503_strong'
              : edge.challenge ? 'challenge' : record.status === 'success' ? 'success' : 'failure';
    state.recent.push({ at: now, type, path: call.path, fingerprint: record.responseFingerprint, category: call.toolCategory, latencyMs }); state.recent = state.recent.filter(item => now - item.at < 120_000);
    state.consecutiveTimeouts = type === 'timeout' ? state.consecutiveTimeouts + 1 : type === 'success' ? 0 : state.consecutiveTimeouts;
    state.blockingResponses = ['403_strong', '429', '503_strong', 'challenge'].includes(type) ? state.blockingResponses + 1 : type === 'success' ? 0 : state.blockingResponses;
    if (type === '429') this.metrics.rateLimitEvents++;
    if (type === 'success' && state.blockState === 'probable_edge_block' && state.healthChecks > 0) {
      state.blockState = 'defensive';
      state.blockedAt = undefined;
      this.emit('EXECUTED', 'edge health check recovered; continuing at defensive rate', call);
    }
    const hadSuccess = state.recent.some(item => item.type === 'success');
    const failingCategories = new Set(state.recent.filter(item => item.type === 'timeout' || item.type === 'failure').map(item => item.category).filter(Boolean));
    const simultaneousFailures = state.recent.filter(item => item.type === 'timeout' || ['403_strong', '429', '503_strong', 'challenge'].includes(item.type)).length;
    if (failingCategories.size >= 2 && state.recent.some(item => item.type === '403_weak')) state.blockingResponses++;
    if ((hadSuccess && (state.consecutiveTimeouts >= 2 || state.blockingResponses >= 2)) || simultaneousFailures >= 3 || edge.challenge) {
      if (state.blockState !== 'probable_edge_block') { this.metrics.wafEvents++; this.emit('STOPPED', 'probable WAF block', call); }
      state.blockState = 'probable_edge_block'; state.blockedAt = now;
      this.abortTarget(call.host, 'probable edge block');
      const area = `${call.host}: active coverage incomplete after probable edge block`;
      if (!this.metrics.incompleteAreas.includes(area)) this.metrics.incompleteAreas.push(area);
    }
  }

  private resolveConflicts(record: EvidenceRecord): void {
    if (!['port_discovery', 'service_detection', 'full_port_scan'].includes(record.toolCategory)) return;
    const call = normalizeToolCall(record.toolName, { parameters: record.requestParameters });
    const open = new Set([...record.rawOutput.matchAll(/(\d+)\/tcp\s+open/g)].map(match => Number(match[1])));
    const prior = [...this.records].slice(0, -1).reverse().find(item => ['port_discovery', 'service_detection', 'full_port_scan'].includes(item.toolCategory) && normalizeToolCall(item.toolName, { parameters: item.requestParameters }).host === call.host);
    if (!prior) return;
    const priorOpen = new Set([...prior.rawOutput.matchAll(/(\d+)\/tcp\s+open/g)].map(match => Number(match[1])));
    const changed = [...new Set([...open, ...priorOpen])].filter(port => open.has(port) !== priorOpen.has(port));
    if (!changed.length) return;
    const network = this.networkState(call.host);
    const conflict: EvidenceConflict = { target: call.host, subject: `ports ${changed.join(',')}`, recordIds: [prior.id, record.id], explanation: network.blockState === 'probable_edge_block' || network.edgeSurface ? 'Temporary edge filtering or scanner blocking is probable.' : 'Network state or scan configuration changed; targeted verification is required.', finalState: network.edgeSurface ? 'reachable through edge; later filtering remains possible' : 'conflicting observations retained', confidence: network.edgeSurface ? 0.75 : 0.5, verificationRequired: true, recommendedVerification: `Run one targeted port-discovery check for ${changed.join(',')} after edge backoff; mark repeatReason=contradiction_verification.` };
    this.conflicts.push(conflict); this.metrics.contradictions++; record.confidence = Math.min(record.confidence, conflict.confidence);
  }

  canStartExploit(params: { target: string; validatedFindings: number; activeTestingAllowed: boolean; targetReachable: boolean; requiredToolAvailable: boolean }): { allowed: boolean; phaseStatus: 'ready' | 'no_validated_targets' | 'blocked' | 'not_authorized' | 'unavailable'; reason: string } {
    if (params.validatedFindings <= 0) return { allowed: false, phaseStatus: 'no_validated_targets', reason: 'No validated finding exists.' };
    if (!params.activeTestingAllowed) return { allowed: false, phaseStatus: 'not_authorized', reason: 'Active testing is not authorized.' };
    if (!params.requiredToolAvailable) return { allowed: false, phaseStatus: 'unavailable', reason: 'Required exploit-validation tool is unavailable.' };
    const network = this.networkState(params.target);
    if (!params.targetReachable || network.blockState === 'probable_edge_block') return { allowed: false, phaseStatus: 'blocked', reason: 'Target is unreachable or under probable edge blocking.' };
    const budget = this.getBudget(params.target);
    if (budget.remaining.exploit_validation_budget <= 0 || budget.remaining.total_request_budget <= 0) return { allowed: false, phaseStatus: 'blocked', reason: 'Exploit request budget is exhausted.' };
    return { allowed: true, phaseStatus: 'ready', reason: 'Validated evidence and execution prerequisites are present.' };
  }
}

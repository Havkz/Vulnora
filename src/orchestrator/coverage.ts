import { isIP } from 'node:net';
import { DEFAULT_WEB_WORDLIST } from '../arsenal/catalog.js';
import type { EvidenceRecord, NetworkContext, TargetBudgets } from './tool-orchestrator.js';

export type CoverageCapability =
  | 'dns_enumeration' | 'http_probe' | 'tls_analysis' | 'header_analysis'
  | 'technology_detection' | 'port_discovery' | 'service_detection'
  | 'content_discovery' | 'api_discovery' | 'vulnerability_scanning'
  | 'targeted_validation' | 'authentication_testing' | 'input_surface' | 'reporting';

export type CoverageStatus =
  | 'not_started' | 'in_progress' | 'completed' | 'completed_negative' | 'blocked'
  | 'failed_retryable' | 'failed_terminal' | 'incomplete' | 'not_applicable';

export interface CoverageEntry {
  capability: CoverageCapability;
  status: CoverageStatus;
  evidenceRecordIds: string[];
  reason?: string;
}

export interface CoverageSnapshot {
  target: string;
  entries: Record<CoverageCapability, CoverageEntry>;
  complete: boolean;
  retryable: CoverageCapability[];
  incomplete: CoverageCapability[];
}

export interface CoverageRecoveryAction {
  capability: CoverageCapability;
  toolName: string;
  parameters: Record<string, unknown>;
  repeatReason?: 'previous_failure' | 'materially_different_configuration';
  description: string;
  requiredCapability?: CoverageCapability;
  missingEvidence?: string;
  retryAfterCapability?: CoverageCapability;
}

const CAPABILITIES: CoverageCapability[] = [
  'dns_enumeration', 'http_probe', 'tls_analysis', 'header_analysis', 'technology_detection',
  'port_discovery', 'service_detection', 'content_discovery', 'api_discovery',
  'vulnerability_scanning', 'targeted_validation', 'authentication_testing', 'input_surface', 'reporting',
];

const terminalErrors = new Set(['scope_denied', 'not_authorized', 'budget_exceeded', 'dependency_missing', 'waf_blocked']);
const retryableErrors = new Set(['timeout', 'network_unreachable', 'tool_crash', 'target_error', 'configuration_error']);

function belongs(record: EvidenceRecord, capability: CoverageCapability): boolean {
  const name = record.toolName;
  if (capability === 'dns_enumeration') return record.toolCategory === 'dns' || record.toolCategory === 'passive_recon';
  if (capability === 'http_probe') return record.toolCategory === 'http_fetch';
  if (capability === 'tls_analysis') return record.toolCategory === 'tls';
  if (capability === 'header_analysis') return /^(?:header_analysis|cookie_analysis|csp_analysis|clickjacking_test)$/.test(name);
  if (capability === 'technology_detection') return /^(?:technology_detect|version_detect|whatweb_tool)$/.test(name);
  if (capability === 'port_discovery') return record.toolCategory === 'port_discovery' || record.toolCategory === 'full_port_scan';
  if (capability === 'service_detection') return record.toolCategory === 'service_detection';
  if (capability === 'content_discovery') return /^(?:dir_bruteforce|ffuf_fuzz|ffuf_tool|gobuster_tool|feroxbuster_tool|katana_tool)$/.test(name);
  if (capability === 'api_discovery') return name === 'api_endpoint_discovery';
  if (capability === 'vulnerability_scanning') return /^(?:nuclei_scan|nuclei_tool|nikto_tool)$/.test(name);
  if (capability === 'targeted_validation') return /(?:sqli|xss|ssti|lfi|redirect|cors|http_methods)/.test(name);
  if (capability === 'authentication_testing') return /(?:auth|login|jwt|password_spray)/.test(`${name} ${record.target}`);
  if (capability === 'input_surface') return /(?:sqli|xss|ssti|lfi|api_endpoint|ffuf)/.test(name);
  return record.toolCategory === 'reporting';
}

function classify(records: EvidenceRecord[]): CoverageStatus {
  if (!records.length) return 'not_started';
  if (records.some(record => record.executionStatus === 'executed' && record.resultType === 'positive')) return 'completed';
  if (records.some(record => record.executionStatus === 'executed' && ['negative', 'empty', 'inconclusive'].includes(record.resultType))) return 'completed_negative';
  const last = records.at(-1)!;
  if (last.executionStatus === 'blocked' || (last.errorType && terminalErrors.has(last.errorType))) return 'failed_terminal';
  if (last.executionStatus === 'deferred') return last.errorType === 'waf_blocked' ? 'failed_terminal' : 'failed_retryable';
  if (last.errorType && retryableErrors.has(last.errorType)) return 'failed_retryable';
  return last.executionStatus === 'skipped' ? 'incomplete' : 'failed_retryable';
}

function targetUrl(target: string): URL {
  const address = target.trim();
  return new URL(/^https?:\/\//i.test(address) ? address : `https://${isIP(address) === 6 ? `[${address}]` : address}`);
}

export function evaluateCoverage(target: string, records: EvidenceRecord[], reportingCompleted = false): CoverageSnapshot {
  const host = targetUrl(target).hostname;
  const hostRecords = records.filter(record => {
    try { return targetUrl(record.target).hostname === host; }
    catch { return record.target === target; }
  });
  const entries = Object.fromEntries(CAPABILITIES.map(capability => {
    const matching = hostRecords.filter(record => belongs(record, capability));
    const status = capability === 'reporting' && reportingCompleted ? 'completed' : classify(matching);
    return [capability, { capability, status, evidenceRecordIds: matching.map(record => record.id) } satisfies CoverageEntry];
  })) as Record<CoverageCapability, CoverageEntry>;

  const httpAvailable = ['completed', 'completed_negative'].includes(entries.http_probe.status);
  if (!httpAvailable && entries.http_probe.status === 'failed_terminal') {
    for (const capability of ['header_analysis', 'technology_detection', 'content_discovery', 'api_discovery', 'authentication_testing', 'input_surface'] as CoverageCapability[]) {
      if (entries[capability].status === 'not_started') entries[capability] = { ...entries[capability], status: 'not_applicable', reason: 'No reachable HTTP surface.' };
    }
  }
  if (entries.vulnerability_scanning.status === 'completed_negative' && entries.targeted_validation.status === 'not_started') {
    entries.targeted_validation = { ...entries.targeted_validation, status: 'not_applicable', reason: 'No candidate finding requiring targeted validation.' };
  }
  const discoveryClosedWithoutSurface = ['completed_negative', 'failed_terminal', 'not_applicable'].includes(entries.content_discovery.status)
    && ['completed_negative', 'failed_terminal', 'not_applicable'].includes(entries.api_discovery.status);
  if (discoveryClosedWithoutSurface) {
    if (entries.authentication_testing.status === 'not_started') entries.authentication_testing = { ...entries.authentication_testing, status: 'not_applicable', reason: 'No authentication surface identified.' };
    if (entries.input_surface.status === 'not_started') entries.input_surface = { ...entries.input_surface, status: 'not_applicable', reason: 'No testable input surface identified.' };
  }
  // A successful HTTP/TLS observation is sufficient to seed the corresponding web port.
  if (entries.port_discovery.status === 'not_started' && (httpAvailable || ['completed', 'completed_negative'].includes(entries.tls_analysis.status))) {
    entries.port_discovery = { ...entries.port_discovery, status: 'completed', reason: 'Known web port inferred from successful HTTP/TLS evidence.' };
  }
  const incomplete = CAPABILITIES.filter(capability => !['completed', 'completed_negative', 'failed_terminal', 'not_applicable'].includes(entries[capability].status));
  const retryable = incomplete.filter(capability => ['not_started', 'failed_retryable', 'incomplete'].includes(entries[capability].status));
  return { target, entries, complete: incomplete.length === 0, retryable, incomplete };
}

export function planCoverageRecovery(params: {
  snapshot: CoverageSnapshot;
  records: EvidenceRecord[];
  availableTools: Set<string>;
  attempts: Partial<Record<CoverageCapability, number>>;
  network: NetworkContext;
  budget: { remaining: TargetBudgets };
  includeValidation: boolean;
}): CoverageRecoveryAction | undefined {
  const { snapshot, availableTools, attempts, network, budget } = params;
  if (network.blockState === 'probable_edge_block' || budget.remaining.tool_call_budget <= 0 || budget.remaining.total_request_budget <= 0) return undefined;
  const count = (capability: CoverageCapability) => attempts[capability] || 0;
  const open = (capability: CoverageCapability) => snapshot.retryable.includes(capability);
  const address = targetUrl(snapshot.target);
  const target = address.hostname.replace(/^\[|\]$/g, '');
  const url = address.href;
  const webPorts = [...new Set([80, 443, Number(address.port) || 443])].join(',');

  if (open('dns_enumeration') && count('dns_enumeration') < 1 && availableTools.has('dns_lookup')) return { capability: 'dns_enumeration', toolName: 'dns_lookup', parameters: { domain: target, type: 'A' }, repeatReason: 'previous_failure', description: 'DNS baseline recovery' };
  if (open('http_probe') && count('http_probe') < 2 && availableTools.has('http_request')) return { capability: 'http_probe', toolName: 'http_request', parameters: { url, method: 'GET', headers: {}, body: '' }, repeatReason: 'previous_failure', description: 'HTTP baseline recovery' };
  if (open('tls_analysis') && count('tls_analysis') < 1 && availableTools.has('ssl_scan')) return { capability: 'tls_analysis', toolName: 'ssl_scan', parameters: { host: target, port: address.protocol === 'https:' ? Number(address.port || 443) : 443 }, repeatReason: 'previous_failure', description: 'TLS coverage recovery' };
  if (open('header_analysis') && count('header_analysis') < 1 && availableTools.has('header_analysis')) return { capability: 'header_analysis', toolName: 'header_analysis', parameters: { url }, repeatReason: 'previous_failure', description: 'Security-header coverage recovery' };
  if (open('technology_detection') && count('technology_detection') < 1 && availableTools.has('technology_detect')) return { capability: 'technology_detection', toolName: 'technology_detect', parameters: { url }, repeatReason: 'previous_failure', description: 'Technology coverage recovery' };

  if (open('port_discovery') && count('port_discovery') < 3) {
    const attempt = count('port_discovery');
    if (attempt === 0 && availableTools.has('nmap_scan')) return { capability: 'port_discovery', toolName: 'nmap_scan', parameters: { target, flags: '--top-ports 1000 -T4' }, repeatReason: 'previous_failure', description: 'Top-1000 port discovery recovery' };
    if (attempt <= 1 && availableTools.has('nmap_scan')) return { capability: 'port_discovery', toolName: 'nmap_scan', parameters: { target, ports: '21,22,25,53,80,110,143,443,445,587,993,995,1433,3000,3306,3389,5432,6379,8000,8080,8443' }, repeatReason: 'materially_different_configuration', description: 'Reduced common-port fallback' };
    if (availableTools.has('port_scan')) return { capability: 'port_discovery', toolName: 'port_scan', parameters: { target, ports: '22,25,53,80,443,3000,8000,8080,8443', timeout: 3000 }, repeatReason: 'materially_different_configuration', description: 'Minimal common-port fallback' };
  }
  if (open('service_detection') && count('service_detection') < 2 && availableTools.has('nmap_scan')) {
    return { capability: 'service_detection', toolName: 'nmap_scan', parameters: { target, ports: webPorts, flags: '-sV --version-light' }, repeatReason: 'materially_different_configuration', description: 'Service detection on evidenced web ports', requiredCapability: 'port_discovery', missingEvidence: 'Open-port evidence', retryAfterCapability: 'port_discovery' };
  }
  if (open('content_discovery') && count('content_discovery') < 3) {
    if (count('content_discovery') === 0 && availableTools.has('ffuf_fuzz')) {
      const fuzz = new URL(url); fuzz.pathname = fuzz.pathname.replace(/\/?$/, '/FUZZ');
      return { capability: 'content_discovery', toolName: 'ffuf_fuzz', parameters: { url: fuzz.href, wordlist: DEFAULT_WEB_WORDLIST, mc: '200,204,301,302,307,401,403' }, description: 'Bounded FFUF content discovery' };
    }
    for (const toolName of ['feroxbuster_tool', 'gobuster_tool', 'dir_bruteforce']) if (availableTools.has(toolName)) return { capability: 'content_discovery', toolName, parameters: toolName === 'dir_bruteforce' ? { url, wordlist: 'common' } : { url, wordlist: DEFAULT_WEB_WORDLIST }, repeatReason: 'materially_different_configuration', description: `Content discovery fallback via ${toolName}` };
  }
  if (open('api_discovery') && count('api_discovery') < 1 && availableTools.has('api_endpoint_discovery')) return { capability: 'api_discovery', toolName: 'api_endpoint_discovery', parameters: { url, wordlist: 'common' }, description: 'Bounded API discovery' };
  if (params.includeValidation && open('vulnerability_scanning') && count('vulnerability_scanning') < 1 && availableTools.has('nuclei_scan')) return { capability: 'vulnerability_scanning', toolName: 'nuclei_scan', parameters: { target: url, severity: 'critical,high,medium' }, description: 'Automated vulnerability coverage' };
  if (params.includeValidation && open('targeted_validation') && count('targeted_validation') < 1 && availableTools.has('http_methods_test')) return { capability: 'targeted_validation', toolName: 'http_methods_test', parameters: { url }, description: 'Low-impact targeted HTTP validation' };
  return undefined;
}

export const RECON_COVERAGE: CoverageCapability[] = [
  'dns_enumeration', 'http_probe', 'tls_analysis', 'header_analysis', 'technology_detection',
  'port_discovery', 'service_detection', 'content_discovery', 'api_discovery',
];

export const VALIDATION_COVERAGE: CoverageCapability[] = [
  'vulnerability_scanning', 'targeted_validation', 'authentication_testing', 'input_surface',
];

export function openCoverage(snapshot: CoverageSnapshot, required: CoverageCapability[], terminalized: Set<CoverageCapability> = new Set()): CoverageCapability[] {
  return required.filter(capability => !terminalized.has(capability)
    && !['completed', 'completed_negative', 'failed_terminal', 'not_applicable'].includes(snapshot.entries[capability].status));
}

export function missionCompletionStatus(snapshots: CoverageSnapshot[]): 'COMPLETED' | 'COMPLETED_WITH_WARNINGS' | 'PARTIALLY_COMPLETED' | 'BLOCKED' | 'FAILED' {
  const entries = snapshots.flatMap(snapshot => Object.values(snapshot.entries));
  if (entries.some(entry => entry.status === 'failed_retryable' || entry.status === 'not_started' || entry.status === 'incomplete')) return 'PARTIALLY_COMPLETED';
  if (entries.some(entry => entry.status === 'failed_terminal' || entry.status === 'blocked')) return 'COMPLETED_WITH_WARNINGS';
  return 'COMPLETED';
}

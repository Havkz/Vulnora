import type { LLMToolDefinition, Target, Task, Vulnerability } from '../types/index.js';

export type AgentPromptProfileName = 'large_model' | 'small_model_30b';
export type EvidenceStatus = 'observed' | 'suspected' | 'validated' | 'exploitable';

export interface AgentPromptProfile {
  name: AgentPromptProfileName;
  maxTools: number;
  maxToolCalls: number;
  maxIterations: number;
  /** Cumulative model input + output tokens across the whole agent run. */
  maxTotalTokens: number;
  responseTokens: number;
  finalResponseTokens: number;
  findingLimit: number;
  evidenceChars: number;
  sourceChars: number;
}

export const AGENT_PROMPT_PROFILES: Record<AgentPromptProfileName, AgentPromptProfile> = {
  large_model: {
    name: 'large_model', maxTools: 20, maxToolCalls: 20, maxIterations: 15,
    maxTotalTokens: 50_000, responseTokens: 4096, finalResponseTokens: 2048,
    findingLimit: 24, evidenceChars: 500, sourceChars: 6000,
  },
  small_model_30b: {
    name: 'small_model_30b', maxTools: 12, maxToolCalls: 12, maxIterations: 12,
    maxTotalTokens: 8_000, responseTokens: 1536, finalResponseTokens: 1024,
    findingLimit: 8, evidenceChars: 180, sourceChars: 1200,
  },
};

/** Resolve runtime overrides without mutating the shared profile constants. */
export function resolveAgentPromptProfile(name: AgentPromptProfileName): AgentPromptProfile {
  const profile = AGENT_PROMPT_PROFILES[name];
  if (name !== 'small_model_30b') return { ...profile };
  const configured = Number(process.env.T3MP3ST_SMALL_MODEL_TOTAL_TOKEN_BUDGET || profile.maxTotalTokens);
  const maxTotalTokens = Number.isFinite(configured) && configured >= 2_000
    ? Math.min(50_000, Math.round(configured))
    : profile.maxTotalTokens;
  return { ...profile, maxTotalTokens };
}

export interface PromptSecurityContext {
  allowedHosts?: string[];
  allowedPorts?: number[];
  authorization?: string;
  receipt?: string;
  intensity?: string;
  forbidden?: string[];
  rateLimit?: string;
  stopConditions?: string[];
  intrusiveAllowed?: boolean;
  credentialToolsAllowed?: boolean;
  /** Individually approved tools from the existing ApprovalController. */
  approvedTools?: string[];
}

const FUNCTION_GROUPS: Array<{ group: string; matches: RegExp }> = [
  { group: 'port-scan', matches: /^(?:nmap_scan|port_scan|naabu(?:_tool)?)$/ },
  { group: 'http-client', matches: /^(?:http_request|curl_request)$/ },
  { group: 'content-discovery', matches: /^(?:dir_bruteforce|ffuf_fuzz|ffuf_tool|gobuster_tool|feroxbuster_tool|katana_tool)$/ },
  { group: 'technology', matches: /^(?:technology_detect|whatweb_tool)$/ },
  { group: 'tls', matches: /^(?:ssl_scan|testssl_tool)$/ },
  { group: 'subdomains', matches: /^(?:subdomain_enum|subfinder_tool|amass_tool)$/ },
];

const TOOL_PRIORITY: Record<string, string[]> = {
  recon: [
    'dns_lookup', 'whois_lookup', 'subdomain_enum', 'nmap_scan', 'http_request',
    'technology_detect', 'robots_txt_fetch', 'header_analysis', 'ssl_scan',
    'api_endpoint_discovery', 'waybackurls_tool', 'network_trace',
  ],
  scanner: [
    'nuclei_scan', 'http_request', 'header_analysis', 'ssl_scan', 'csp_analysis',
    'cors_check', 'cookie_analysis', 'http_methods_test', 'clickjacking_test',
    'technology_detect', 'version_detect', 'api_endpoint_discovery', 'open_redirect_test',
  ],
  exploiter: [
    'curl_request', 'sqli_scan', 'xss_scan', 'ssti_test', 'lfi_test',
    'open_redirect_test', 'nuclei_scan', 'http_methods_test', 'api_endpoint_discovery',
    'jwt_decode', 'header_analysis', 'technology_detect', 'password_spray', 'hash_crack',
  ],
  analyst: [
    'cve_lookup', 'ssl_scan', 'header_analysis', 'csp_analysis', 'cors_check',
    'cookie_analysis', 'http_request', 'dns_lookup', 'technology_detect',
    'version_detect', 'jwt_decode', 'base64_decode',
  ],
  default: [
    'http_request', 'nmap_scan', 'dns_lookup', 'technology_detect', 'header_analysis',
    'ssl_scan', 'nuclei_scan', 'api_endpoint_discovery', 'cve_lookup', 'jwt_decode',
  ],
};

const CREDENTIAL_TOOLS = /^(?:password_spray|hash_crack|hydra_tool)$/;
const INTRUSIVE_TOOLS = /(?:exploit|metasploit|msf|sqlmap|password_spray|hydra|command_exec|shell)/i;
const NETWORK_TOOLS = /(?:nmap|port_scan|naabu|http|curl|dns|whois|subdomain|subfinder|amass|nuclei|ffuf|gobuster|ferox|katana|ssl|testssl|technology|whatweb|header|version|cors|csp|cookie|clickjack|redirect|sqli|xss|ssti|lfi|trace|robots|api_endpoint)/i;

function groupForTool(name: string): string {
  return FUNCTION_GROUPS.find(entry => entry.matches.test(name))?.group || name;
}

export function selectRelevantTools(
  definitions: LLMToolDefinition[],
  task: Task,
  profile: AgentPromptProfile,
  security: PromptSecurityContext = {},
  hasTarget = true
): LLMToolDefinition[] {
  const byName = new Map(definitions.map(definition => [definition.name, definition]));
  const priority = TOOL_PRIORITY[task.operatorType] || TOOL_PRIORITY.default;
  const selected: LLMToolDefinition[] = [];
  const usedGroups = new Set<string>();
  const approvedTools = new Set(security.approvedTools || []);
  const consider = (definition: LLMToolDefinition | undefined): void => {
    if (!definition || selected.length >= profile.maxTools) return;
    if (!hasTarget && NETWORK_TOOLS.test(definition.name)) return;
    if (!security.intrusiveAllowed && INTRUSIVE_TOOLS.test(definition.name) && !approvedTools.has(definition.name)) return;
    if (!security.credentialToolsAllowed && CREDENTIAL_TOOLS.test(definition.name) && !approvedTools.has(definition.name)) return;
    const group = groupForTool(definition.name);
    if (usedGroups.has(group)) return;
    usedGroups.add(group);
    selected.push(definition);
  };

  for (const name of priority) consider(byName.get(name));
  for (const definition of definitions) consider(definition);
  return selected;
}

function oneLine(value: unknown, limit: number): string {
  const clean = String(value ?? '').replace(/\s+/g, ' ').replace(/\.\.\.\[truncated\]\.\.\.|\.\.\.\s*\(truncated[^)]*\)\s*\.\.\./gi, '').trim();
  if (!clean) return 'No concise evidence recorded.';
  if (clean.length <= limit) return /[.!?]$/.test(clean) ? clean : `${clean}.`;
  const sentences = clean.match(/[^.!?]+[.!?]+/g) || [];
  const complete = sentences.find(sentence => sentence.trim().length <= limit)?.trim();
  if (complete) return complete;
  const words = clean.slice(0, limit).replace(/\s+\S*$/, '').replace(/[,:;\-\s]+$/, '');
  return `${words || clean.slice(0, Math.max(1, limit - 1))}.`;
}

function evidenceStatus(vulnerability: Vulnerability): EvidenceStatus {
  if (vulnerability.evidenceStatus) return vulnerability.evidenceStatus;
  if (vulnerability.exploitAvailable) return 'exploitable';
  if (/\b(?:validated|verified|confirmed)\b/i.test(vulnerability.description)) return 'validated';
  return 'observed';
}

function statusRank(status: EvidenceStatus): number {
  return { suspected: 0, observed: 1, validated: 2, exploitable: 3 }[status];
}

function emailPolicyFinding(vulnerability: Vulnerability): boolean {
  return /\b(?:dmarc|spf|mta-?sts|smtp tls reporting|dkim)\b/i.test(`${vulnerability.name} ${vulnerability.description}`);
}

export function compactKnownEvidence(target: Target | undefined, profile: AgentPromptProfile): string[] {
  if (!target?.vulnerabilities?.length) return ['- No prior vulnerability evidence was supplied.'];
  const deduped = new Map<string, { vuln: Vulnerability; status: EvidenceStatus }>();
  for (const vuln of target.vulnerabilities) {
    const status = evidenceStatus(vuln);
    const key = `${vuln.name.toLowerCase().replace(/\W+/g, ' ').trim()}|${target.address.toLowerCase()}`;
    const prior = deduped.get(key);
    if (!prior || statusRank(status) > statusRank(prior.status)) deduped.set(key, { vuln, status });
  }
  return [...deduped.values()].slice(0, profile.findingLimit).map(({ vuln, status }) => {
    const evidence = oneLine(vuln.evidence || vuln.description, profile.evidenceChars);
    const impact = emailPolicyFinding(vuln)
      ? 'Email-authentication posture only; this does not prove RCE, data access, or authentication bypass.'
      : oneLine(vuln.impact || vuln.description, Math.min(profile.evidenceChars, 200));
    return `- [${status}] ${vuln.name} | target=${target.address} | evidence=${evidence} | impact=${impact}`;
  });
}

function requestsHighImpact(task: Task): boolean {
  return /\b(?:rce|remote code|code execution|data access|data compromise|authentication bypass|auth bypass|unauthorized access)\b/i
    .test(`${task.name} ${task.description}`);
}

function onlyNonExploitEvidence(target?: Target): boolean {
  const findings = target?.vulnerabilities || [];
  return findings.length > 0 && findings.every(vuln => emailPolicyFinding(vuln) || evidenceStatus(vuln) === 'suspected' || evidenceStatus(vuln) === 'observed');
}

function compactSource(source: string | undefined, limit: number): string | undefined {
  if (!source?.trim()) return undefined;
  const lines = source.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const unique = [...new Map(lines.map(line => [line.toLowerCase(), line])).values()];
  const kept: string[] = [];
  let size = 0;
  for (const line of unique) {
    const complete = oneLine(line, Math.min(240, limit));
    if (size + complete.length + 2 > limit) break;
    kept.push(complete);
    size += complete.length + 2;
  }
  return kept.join('\n');
}

function toolPreference(tools: LLMToolDefinition[]): string {
  const names = new Set(tools.map(tool => tool.name));
  const hints: string[] = [];
  if (names.has('http_request')) hints.push('Prefer HTTP for a single read-only request.');
  if (names.has('curl_request')) hints.push('Prefer Curl for one exact request or payload validation.');
  if (names.has('nmap_scan')) hints.push('Use Nmap only when service or port evidence is needed.');
  if (names.has('nuclei_scan')) hints.push('Use Nuclei only for a focused template check.');
  return hints.slice(0, 2).join(' ');
}

export function buildMissionPrompt(args: {
  task: Task;
  target?: Target;
  tools: LLMToolDefinition[];
  profile: AgentPromptProfile;
  security?: PromptSecurityContext;
  sourceContext?: string;
}): string {
  const { task, target, tools, profile } = args;
  const supplied = args.security || {};
  const metadata = target?.metadata || {};
  const allowedHosts = [...new Set([...(supplied.allowedHosts || []), ...(target?.address ? [target.address] : [])])];
  const allowedPorts = [...new Set([...(supplied.allowedPorts || []), ...(target?.port ? [target.port] : []), ...(target?.services || []).map(service => service.port)])];
  const receiptValue = supplied.receipt || String(metadata.authorizationReceipt || metadata.scopeReceipt || metadata.receipt || 'not supplied');
  const hasReceipt = receiptValue !== 'not supplied';
  const authorization = supplied.authorization || (target ? 'Target registered in the active mission; runtime ScopeGuard remains authoritative.' : 'Missing target scope.');
  const forbidden = [...new Set([
    ...(supplied.forbidden || []),
    'destructive actions', 'denial of service',
    ...(!hasReceipt ? ['credential use and intrusive exploitation without a receipt'] : []),
  ])];
  const source = compactSource(args.sourceContext, profile.sourceChars);
  const evidence = compactKnownEvidence(target, profile);
  const contradiction = requestsHighImpact(task) && onlyNonExploitEvidence(target)
    ? 'Current evidence is limited to observed email/security configuration issues. It does not support RCE, data access, or authentication bypass. Do not claim exploitation. Select one allowed testable path or report not_exploitable/inconclusive.'
    : 'Treat observed and suspected items as leads only. Claim exploitation only from reproducible evidence marked exploitable.';

  const sections = [
    'ROLE',
    `You are the ${task.operatorType} planning agent for an authorized security assessment.`,
    'Specialization: Validate only reproducible, in-scope security findings relevant to the mission.',
    'Use function calls for tools. Tool schemas are the authoritative tool documentation.',
    'Never invent tool results, evidence, access, or impact.',
    '',
    'SCOPE',
    `Targets: ${allowedHosts.length ? allowedHosts.join(', ') : 'none'}`,
    `Ports: ${allowedPorts.length ? allowedPorts.join(', ') : 'not specified'}`,
    `Authorization: ${authorization}`,
    `Receipt: ${receiptValue}`,
    `Approved intrusive tools: ${supplied.approvedTools?.length ? supplied.approvedTools.join(', ') : 'none'}`,
    `Limits: ${supplied.intensity || (hasReceipt ? 'receipt-defined intensity only' : 'non-intrusive and read-only only')}`,
    `Forbidden: ${forbidden.join(', ')}`,
    `Rate limit: ${supplied.rateLimit || 'Use tool defaults; stop on throttling or instability.'}`,
    `Stop conditions: ${(supplied.stopConditions || ['validated result', 'missing scope', 'no testable path', 'two steps without new relevant evidence']).join(', ')}`,
    '',
    'MISSION',
    `Objective: ${oneLine(task.description, profile.name === 'small_model_30b' ? 320 : 600)}`,
    'Success condition: One reproducible, in-scope result supported by a real tool response.',
    'Stop condition: Validated, not exploitable, inconclusive, blocked, or two steps without new relevant evidence.',
    '',
    'KNOWN EVIDENCE',
    ...evidence,
    '',
    'CONSTRAINT',
    contradiction,
    !allowedHosts.length ? 'Scope is missing. Do not request network, intrusive, or credential-based tools.' : '',
    !hasReceipt ? 'No receipt is present. Do not request intrusive or credential-based tools.' : '',
    '',
    'TOOL USE',
    `${tools.length} relevant function schemas are available. ${toolPreference(tools)}`.trim(),
    `Token budget: ${profile.maxTotalTokens} cumulative model tokens. This includes model prompt/input and response/output tokens across all steps; tool output counts when it is included in a later model prompt.`,
    profile.name === 'large_model'
      ? 'Decision rationale: Explain briefly why the selected test is highest-value, what evidence would advance the mission, and what result would stop it. Do not restate known evidence.'
      : 'Decision rationale: Use one short evidence-linked sentence.',
    'Do not repeat an identical or functionally equivalent test.',
    '',
    'WORKFLOW',
    '1. Check scope and authorization.',
    '2. Check which findings are actually testable.',
    '3. Select exactly one best next test.',
    '4. Request the most specific available tool.',
    '5. Evaluate only the real tool result.',
    '6. Never invent results or impact.',
    '7. Do not repeat equivalent tests.',
    '8. Stop on a validated result, missing scope, or no testable path.',
    '',
    'OUTPUT',
    'RESULT',
    'Status: validated | not_exploitable | inconclusive | blocked',
    '',
    'Finding:',
    'Target:',
    'Evidence:',
    'Impact:',
    'Actions performed:',
    'Limitations:',
    'Recommended next step:',
  ];
  if (source) sections.splice(sections.indexOf('CONSTRAINT'), 0, 'SOURCE CONTEXT', source, '');
  return sections.filter((line, index, all) => line !== '' || all[index - 1] !== '').join('\n').trim();
}

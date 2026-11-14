import { isIP } from 'node:net';
import { normalizeHostname, validateProjectTarget } from './targets.js';

export const ASSESSMENT_RISKS = ['local_read', 'passive', 'active', 'intrusive', 'credential', 'dangerous'] as const;
export type AssessmentRisk = typeof ASSESSMENT_RISKS[number];

export interface AssessmentRules {
  scopeHosts: string[];
  excludedHosts: string[];
  excludedTools: string[];
  excludedRisks?: AssessmentRisk[];
  requestsPerSecond?: number;
}

export function validateRequestRate(value: unknown): asserts value is number | undefined {
  if (value !== undefined && (!Number.isInteger(value) || Number(value) < 1 || Number(value) > 1000)) {
    throw new Error('Rate limit must be an integer from 1 to 1000 requests per second per host.');
  }
}

/** Accept only host rules we can enforce; never silently discard a URL path or CIDR. */
export function normalizeAssessmentRules(value: unknown = {}, target?: string): AssessmentRules {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid assessment rules.');
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(key => !['scopeHosts', 'excludedHosts', 'excludedTools', 'excludedRisks', 'requestsPerSecond'].includes(key))) {
    throw new Error('Unknown assessment rule.');
  }
  function list(key: string, host: boolean): string[] {
    const values = raw[key] === undefined ? [] : raw[key];
    if (!Array.isArray(values) || values.length > 128 || values.some(item => typeof item !== 'string')) throw new Error(`Invalid ${key} list.`);
    return [...new Set(values.map((item: string) => {
      const text = item.trim();
      if (!host) {
        if (!/^[a-z][a-z0-9_]{0,99}$/.test(text)) throw new Error(key === 'excludedRisks' ? 'Excluded risk classes must use their exact names.' : 'Excluded tools must be exact tool IDs.');
        return text;
      }
      const parsed = validateProjectTarget(text);
      if (parsed.kind === 'url') throw new Error('Scope and exclusions require bare hostnames or IPs, without paths, ports, wildcards or CIDRs.');
      return normalizeHostname(parsed.hostname);
    }))].sort();
  }
  const excludedRisks = list('excludedRisks', false);
  if (excludedRisks.some(risk => !ASSESSMENT_RISKS.includes(risk as AssessmentRisk))) throw new Error('Unknown excluded risk class.');
  validateRequestRate(raw.requestsPerSecond);
  const rules: AssessmentRules = { scopeHosts: list('scopeHosts', true), excludedHosts: list('excludedHosts', true), excludedTools: list('excludedTools', false),
    ...(excludedRisks.length ? { excludedRisks: excludedRisks as AssessmentRisk[] } : {}),
    ...(raw.requestsPerSecond === undefined ? {} : { requestsPerSecond: raw.requestsPerSecond }) };
  if (target) {
    const hostname = normalizeHostname(validateProjectTarget(target).hostname);
    if (rules.excludedHosts.some(host => hostname === host || (!isIP(host) && hostname.endsWith('.' + host)))) {
      throw new Error('The primary target is excluded by these assessment rules.');
    }
  }
  return rules;
}

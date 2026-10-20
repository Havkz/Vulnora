import type { FallbackPolicy } from '../types/index.js';

export const DEFAULT_FALLBACK_POLICY: Readonly<FallbackPolicy> = Object.freeze({
  enabled: true, onApiError: true, onRateLimit: true, onRefusal: false,
});

export type RefusalKind = 'security_refusal' | 'technical_refusal' | 'unclear_refusal';

/** Called only after a provider has actually declined; quoted tool output is not a refusal. */
export function classifyRefusal(content: string, finishReason?: string): RefusalKind {
  const prose = content.replace(/```[\s\S]*?```/g, '').split('\n')
    .filter(line => !line.trim().startsWith('>')).join('\n');
  if (finishReason === 'content_filter' || finishReason === 'refusal' || /\b(?:safety|policy|policies|guidelines|ethical|harmful|malicious|unauthorized|illegal|cybersecurity risk|trusted access for cyber|weaponiz\w*|guardrails?|sicherheitsrichtlinie\w*|sicherheitsgründen|unautorisiert\w*|schädlich\w*|illegal\w*)\b/i.test(prose)) {
    return 'security_refusal';
  }
  if (/\b(?:network|connection|service unavailable|quota|rate limit|context length|missing (?:tool|capability)|no (?:network|browser|tool) access|timeout|timed out|verbindungsfehler|zeitüberschreitung)\b/i.test(prose)) {
    return 'technical_refusal';
  }
  return 'unclear_refusal';
}

export function permitsFallback(reason: string, policy: FallbackPolicy = DEFAULT_FALLBACK_POLICY): boolean {
  if (policy.enabled !== true || reason === 'security_refusal') return false;
  if (reason === 'refusal' || reason.endsWith('_refusal')) return policy.onRefusal === true;
  if (reason === 'rate_limit' || reason === 'quota') return policy.onRateLimit === true;
  return policy.onApiError === true;
}

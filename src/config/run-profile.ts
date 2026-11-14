import { open } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { CLI_PROVIDERS, type InferenceOptions } from '../cli-inference.js';
import { normalizeAssessmentRules } from '../projects/assessment.js';
import { validateProjectName, validateProjectTarget } from '../projects/targets.js';
import type { ScanningBehavior } from '../projects/store.js';

export interface RunOptions extends InferenceOptions {
  target?: string;
  name?: string;
  resume?: string;
  intensity?: ScanningBehavior;
  verbose?: boolean;
  scope?: string[];
  exclude?: string[];
  excludeTool?: string[];
  excludeRisk?: string[];
  rateLimit?: number;
  output?: string;
  reportFormat?: 'markdown' | 'json' | 'both';
}

const textFields = ['target', 'name', 'provider', 'model', 'reasoning', 'intensity', 'fallbackProvider', 'fallbackModel', 'output', 'reportFormat'];
const booleanFields = ['verbose', 'fallbackEnabled', 'fallbackOnApiError', 'fallbackOnRateLimit', 'fallbackOnRefusal'];
const listFields = ['scope', 'exclude', 'excludeTool', 'excludeRisk'];

/** Read-only run defaults. Secrets and provider endpoints remain in central settings. */
export async function loadRunProfile(path: string): Promise<RunOptions> {
  const file = await open(path, 'r');
  let value: unknown;
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > 65536) throw new Error('Run configuration must be a JSON file of at most 64 KiB.');
    const buffer = Buffer.alloc(65537);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length > 65536) throw new Error('Run configuration exceeds 64 KiB.');
    try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length))); }
    catch { throw new Error('Invalid JSON in run configuration.'); }
  } finally { await file.close(); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Run configuration must be an object.');
  const data = value as Record<string, unknown>;
  const allowed = new Set(['version', 'rateLimit', ...textFields, ...booleanFields, ...listFields]);
  if (data.version !== 1 || Object.keys(data).some(key => !allowed.has(key))) throw new Error('Run configuration requires version 1 and supported option names only.');
  for (const key of textFields) {
    if (data[key] !== undefined && (typeof data[key] !== 'string' || !data[key].trim() || data[key].length > 8192 || /[\p{Cc}\p{Cf}]/u.test(data[key]))) {
      throw new Error(`Invalid ${key} in run configuration.`);
    }
  }
  for (const key of booleanFields) {
    if (data[key] !== undefined && typeof data[key] !== 'boolean') throw new Error(`Invalid ${key} in run configuration; expected true or false.`);
  }
  const choices: Record<string, readonly string[]> = {
    provider: CLI_PROVIDERS, fallbackProvider: CLI_PROVIDERS,
    intensity: ['auto', 'stealth', 'aggressive'], reportFormat: ['markdown', 'json', 'both'],
    reasoning: ['low', 'medium', 'high', 'xhigh', 'max', 'ultra'],
  };
  for (const [key, values] of Object.entries(choices)) {
    if (data[key] !== undefined && !values.includes(data[key] as string)) throw new Error(`Invalid ${key} in run configuration.`);
  }
  const { version: _version, ...options } = data;
  const result = options as RunOptions;
  if (result.name !== undefined) validateProjectName(result.name);
  if (result.target !== undefined && validateProjectTarget(result.target).kind !== 'url') throw new Error('Use an explicit HTTP or HTTPS target URL.');
  normalizeAssessmentRules({ scopeHosts: result.scope, excludedHosts: result.exclude, excludedTools: result.excludeTool, excludedRisks: result.excludeRisk, requestsPerSecond: result.rateLimit }, result.target);
  if (result.output) result.output = resolve(dirname(resolve(path)), result.output);
  return result;
}

/** Explicit flags replace file defaults, including whole host/tool lists. */
export function mergeRunOptions(profile: RunOptions, flags: RunOptions): RunOptions {
  const defaults = { ...profile };
  // A model/effort from one provider is not a valid default for another provider.
  if (flags.provider !== undefined && flags.provider !== profile.provider) { delete defaults.model; delete defaults.reasoning; }
  if (flags.fallbackProvider !== undefined && flags.fallbackProvider !== profile.fallbackProvider) delete defaults.fallbackModel;
  return { ...defaults, ...Object.fromEntries(Object.entries(flags).filter(([, value]) => value !== undefined)) };
}

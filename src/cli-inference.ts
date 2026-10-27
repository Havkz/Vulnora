import type { config } from './config/index.js';
import { CLI_REASONING_LEVELS } from './agent/local-agents.js';
import type { CLIReasoningEffort, LLMConfig, LLMProvider } from './types/index.js';

export const CLI_PROVIDERS = ['codex', 'claude', 'local', 'openai', 'anthropic', 'openrouter', 'venice', 'xai', 'gemini', 'litellm', 'deepseek', 'local-agent'];
export interface InferenceOptions {
  provider?: string;
  model?: string;
  reasoning?: CLIReasoningEffort;
  fallbackEnabled?: boolean;
  fallbackProvider?: string;
  fallbackModel?: string;
  fallbackOnApiError?: boolean;
  fallbackOnRateLimit?: boolean;
  fallbackOnRefusal?: boolean;
}

/** Process-local overrides; never change the saved TUI or another CLI's settings. */
export function resolveInference(configuration: Pick<typeof config, 'getLLMConfig' | 'getFallbackSettings'>, options: InferenceOptions): LLMConfig {
  function select(provider?: string, model?: string): LLMConfig {
    if (provider !== undefined && !CLI_PROVIDERS.includes(provider)) throw new Error(`Unknown inference provider: ${provider}`);
    if (model !== undefined && (!model.trim() || model.startsWith('-') || /[\p{Cc}\p{Cf}]/u.test(model))) throw new Error('Invalid model ID.');
    let result = provider === 'claude' ? configuration.getLLMConfig('local-agent', 'claude')
      : configuration.getLLMConfig(provider as LLMProvider | undefined);
    if (model !== undefined) {
      if (result.provider === 'local-agent') result.cliModel = model;
      else result = configuration.getLLMConfig(result.provider, model);
    }
    if (['mock', 'deterministic'].includes(result.provider)) throw new Error('Select an AI inference provider.');
    if (result.provider === 'local' && !result.model?.trim()) throw new Error('Select an installed local model with --model or in Settings.');
    return result;
  }

  const primary = select(options.provider, options.model);
  if (options.reasoning !== undefined) {
    const agent = primary.provider === 'codex' ? 'codex' : primary.provider === 'local-agent' ? primary.model : undefined;
    if ((agent !== 'codex' && agent !== 'claude') || !CLI_REASONING_LEVELS[agent].includes(options.reasoning)) {
      throw new Error('Reasoning is supported only for Codex and Claude, using their available effort levels.');
    }
    primary.reasoningEffort = options.reasoning;
  }
  const saved = configuration.getFallbackSettings();
  primary.fallbackPolicy = {
    enabled: options.fallbackEnabled ?? saved.enabled,
    onApiError: options.fallbackOnApiError ?? saved.onApiError,
    onRateLimit: options.fallbackOnRateLimit ?? saved.onRateLimit,
    onRefusal: options.fallbackOnRefusal ?? saved.onRefusal,
  };
  if (!primary.fallbackPolicy.enabled) primary.fallbackChain = [];
  else if (options.fallbackProvider !== undefined || options.fallbackModel !== undefined
    || (options.fallbackEnabled === true && !primary.fallbackChain?.length)) {
    const fallback = select(options.fallbackProvider ?? saved.provider,
      options.fallbackModel ?? (options.fallbackProvider === undefined ? saved.model || undefined : undefined));
    const { fallbackChain: _chain, fallbackPolicy: _policy, ...entry } = fallback;
    primary.fallbackChain = [entry];
  }
  return primary;
}

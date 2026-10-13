import type { config as settings } from '../config/index.js';
import { detectLocalAgent } from '../agent/local-agents.js';
import { redactSecrets } from '../redact.js';
import type { LLMConfig, LLMProvider } from '../types/index.js';
import { LLMBackbone } from './index.js';
import { createOllamaSession } from './ollama-session.js';

type Configuration = Pick<typeof settings, 'getLLMConfig' | 'get'>;
export interface ProviderReadiness {
  configured: { provider: LLMProvider; model: string };
  primary: { ready: boolean; detail: string };
  local: { ready: boolean; model?: string; detail: string };
  active: { provider: LLMProvider; model: string };
}

/** Check actual inference once, independently of the scan and its fallback ladder. */
export async function validateProvider(config: LLMConfig, signal: AbortSignal, command?: string): Promise<void> {
  signal.throwIfAborted();
  if (config.provider === 'mock' || config.provider === 'deterministic') throw new Error('No AI inference provider selected.');
  if (config.provider === 'codex' || config.provider === 'local-agent') {
    const id = config.provider === 'codex' ? 'codex' : config.model;
    const agent = await detectLocalAgent(id, id === 'codex' ? command : undefined, signal);
    signal.throwIfAborted();
    if (!agent.installed) throw new Error(`${id} CLI is not installed.`);
    if (!agent.ready) throw new Error(`${id} CLI version/authentication is not ready; sign in through its own CLI.`);
  }
  const backbone = new LLMBackbone({ ...config, fallbackChain: [], timeout: Math.min(config.timeout || 90000, 90000) });
  const validation = backbone.validateConfig();
  if (!validation.valid) throw new Error(validation.error || 'Provider configuration is invalid.');
  backbone.setRetryConfig(1, 0);
  const response = await backbone.prompt('Reply with exactly VULNORA_READY. Do not use any tools.', undefined,
    { signal: AbortSignal.any([signal, AbortSignal.timeout(90000)]), maxTokens: 96, temperature: 0 });
  if (!response.includes('VULNORA_READY')) throw new Error('Provider did not return the inference validation token.');
}

/** One CLI lifetime: selected primary, installed/warmed Ollama, then evidence-only execution. */
export class ProviderSession {
  private localSession?: ReturnType<typeof createOllamaSession>;
  private localConfig?: Pick<LLMConfig, 'model' | 'baseUrl'>;
  private effective: LLMConfig = { provider: 'deterministic', model: 'evidence-only' };
  readiness?: ProviderReadiness;
  private abort = () => { void this.stop().catch(() => {}); };

  constructor(private configuration: Configuration, private signal: AbortSignal) {
    signal.addEventListener('abort', this.abort, { once: true });
  }

  async installedModels(): Promise<string[]> {
    const base = (this.configuration.getLLMConfig('local').baseUrl || '').replace(/\/$/, '');
    if (!base.endsWith('/api')) throw new Error('Installed model discovery requires an Ollama /api endpoint.');
    const response = await fetch(`${base}/tags`, { signal: AbortSignal.any([this.signal, AbortSignal.timeout(10000)]) });
    if (!response.ok) throw new Error(`Ollama discovery failed: HTTP ${response.status}`);
    const data = await response.json() as { models?: { name?: unknown }[] };
    if (!Array.isArray(data.models)) throw new Error('Invalid Ollama model response.');
    return [...new Set(data.models.map(model => model.name).filter((name): name is string => typeof name === 'string' && !!name.trim()))];
  }

  async installedAgents(): Promise<string[]> {
    const agents = await Promise.all(['codex', 'claude'].map(id =>
      detectLocalAgent(id, id === 'codex' ? this.configuration.get('codex').command : undefined, this.signal)));
    return agents.filter(agent => agent.installed).map(agent => agent.id);
  }

  getConfig(): LLMConfig {
    return { ...this.effective, fallbackChain: this.effective.fallbackChain?.map(entry => ({ ...entry })) };
  }

  description(): string {
    const state = this.readiness;
    if (!state) return 'Provider initialization pending';
    return `Primary ${state.configured.provider}/${state.configured.model}: ${state.primary.detail}; Ollama: ${state.local.detail}; active ${state.active.provider}/${state.active.model}`;
  }

  async prepare(): Promise<string> {
    this.signal.throwIfAborted();
    this.effective = { provider: 'deterministic', model: 'evidence-only' }; this.readiness = undefined;
    const primary = { ...this.configuration.getLLMConfig(), fallbackChain: [] };
    let local: LLMConfig | undefined;
    const state: ProviderReadiness = {
      configured: { provider: primary.provider, model: primary.model },
      primary: { ready: false, detail: 'not validated' }, local: { ready: false, detail: 'not validated' },
      active: { provider: 'deterministic', model: 'evidence-only' },
    };
    const detail = (error: unknown) => String(redactSecrets(error instanceof Error ? error.message : String(error)));
    try {
      const models = await this.installedModels();
      const chosen = this.configuration.getLLMConfig('local');
      const model = models.includes(chosen.model) ? chosen.model : models.length === 1 ? models[0] : undefined;
      if (!model) throw new Error(models.length ? 'Choose an installed Ollama model in Settings.' : 'No installed Ollama model found.');
      local = { ...chosen, model, fallbackChain: [] };
      if (!this.localSession || this.localConfig?.model !== local.model || this.localConfig.baseUrl !== local.baseUrl) {
        await this.stop();
        this.localSession = createOllamaSession(local);
        this.localConfig = { model: local.model, baseUrl: local.baseUrl };
      }
      await this.localSession.start(); this.signal.throwIfAborted();
      await validateProvider(local, this.signal);
      state.local = { ready: true, model, detail: `${model} ready and held` };
    } catch (error) {
      this.signal.throwIfAborted();
      state.local.detail = detail(error); local = undefined;
      try { await this.stop(); } catch (stopError) { state.local.detail += `; unload: ${detail(stopError)}`; }
    }
    this.signal.throwIfAborted();
    try {
      if (primary.provider === 'local' && local) {
        primary.model = local.model;
      } else if (primary.provider === 'local' && !/\/v\d+(\/|$)/.test(primary.baseUrl || '')) {
        throw new Error(state.local.detail);
      } else await validateProvider(primary, this.signal, this.configuration.get('codex').command);
      state.primary = { ready: true, detail: 'inference ready' };
    } catch (error) { this.signal.throwIfAborted(); state.primary.detail = detail(error); }
    const deterministic = { provider: 'deterministic' as const, model: 'evidence-only' };
    this.effective = state.primary.ready
      ? { ...primary, fallbackChain: [...(primary.provider !== 'local' && local ? [local] : []), deterministic] }
      : local ? { ...local, fallbackChain: [deterministic] } : deterministic;
    state.active = { provider: this.effective.provider, model: this.effective.model };
    this.readiness = state;
    if (!state.primary.ready && !state.local.ready) throw new Error(this.description());
    return this.description();
  }

  async stop(): Promise<void> {
    const held = this.localSession;
    await held?.stop();
    if (this.localSession === held) { this.localSession = undefined; this.localConfig = undefined; }
  }

  async close(): Promise<void> {
    this.signal.removeEventListener('abort', this.abort);
    await this.stop();
  }
}

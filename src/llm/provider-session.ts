import type { config as settings } from '../config/index.js';
import { detectLocalAgent } from '../agent/local-agents.js';
import { redactSecrets } from '../redact.js';
import type { LLMConfig, LLMProvider } from '../types/index.js';
import { LLMBackbone } from './index.js';
import { createOllamaSession } from './ollama-session.js';
import { fetchLocal, stopOwnedOllama } from './local-service.js';

type Configuration = Pick<typeof settings, 'getLLMConfig' | 'get'>;
export interface ProviderProgress { label: string; status: 'active' | 'completed' | 'failed' | 'skipped'; detail?: string }
type ProgressReporter = (step: ProviderProgress) => void;

async function providerStep<T>(report: ProgressReporter | undefined, label: string, run: () => Promise<T>, detail?: string): Promise<T> {
  report?.({ label, status: 'active', detail });
  try {
    const result = await run();
    report?.({ label, status: 'completed', detail });
    return result;
  } catch (error) {
    report?.({ label, status: error instanceof Error && error.name === 'AbortError' ? 'skipped' : 'failed', detail: String(redactSecrets(error instanceof Error ? error.message : String(error))) });
    throw error;
  }
}
export interface ProviderReadiness {
  configured: { provider: LLMProvider; model: string };
  primary: { ready: boolean; detail: string };
  local: { ready: boolean; model?: string; detail: string };
  active: { provider: LLMProvider; model: string };
}

/** Check actual inference once, independently of the scan and its fallback ladder. */
export async function validateProvider(config: LLMConfig, signal: AbortSignal, command?: string, report?: ProgressReporter): Promise<void> {
  signal.throwIfAborted();
  if (config.provider === 'mock' || config.provider === 'deterministic') throw new Error('No AI inference provider selected.');
  if (config.provider === 'codex' || config.provider === 'local-agent') {
    const id = config.provider === 'codex' ? 'codex' : config.model;
    await providerStep(report, `Checking ${id} CLI authentication`, async () => {
      const agent = await detectLocalAgent(id, id === 'codex' ? command : undefined, signal);
      signal.throwIfAborted();
      if (!agent.installed) throw new Error(`${id} CLI is not installed.`);
      if (!agent.ready) throw new Error(`${id} CLI version/authentication is not ready; sign in through its own CLI.`);
    });
  }
  const name = config.provider === 'local' ? 'Ollama' : config.provider === 'local-agent' ? config.model : config.provider;
  await providerStep(report, `Testing ${name} inference`, async () => {
    const backbone = new LLMBackbone({ ...config, fallbackChain: [], timeout: Math.min(config.timeout || 90000, 90000) });
    const validation = backbone.validateConfig();
    if (!validation.valid) throw new Error(validation.error || 'Provider configuration is invalid.');
    backbone.setRetryConfig(1, 0);
    const response = await backbone.prompt('Reply with exactly VULNORA_READY. Do not use any tools.', undefined,
      { signal: AbortSignal.any([signal, AbortSignal.timeout(90000)]), maxTokens: 96, temperature: 0 });
    if (!response.includes('VULNORA_READY')) throw new Error('Provider did not return the inference validation token.');
  }, config.model);
}

/** Keep the chosen primary first; load local fallback only when a request needs it. */
export class ProviderSession {
  private localSession?: ReturnType<typeof createOllamaSession>;
  private localConfig?: Pick<LLMConfig, 'model' | 'baseUrl'>;
  private effective: LLMConfig = { provider: 'deterministic', model: 'evidence-only' };
  readiness?: ProviderReadiness;
  private abort = () => { void this.stop().catch(() => {}); };

  constructor(private configuration: Configuration, private signal: AbortSignal) {
    signal.addEventListener('abort', this.abort, { once: true });
  }

  async installedModels(signal = this.signal): Promise<string[]> {
    const base = (this.configuration.getLLMConfig('local').baseUrl || '').replace(/\/$/, '');
    const ollama = base.endsWith('/api');
    const key = this.configuration.getLLMConfig('local').apiKey;
    const response = await fetchLocal(`${base}/${ollama ? 'tags' : 'models'}`, {
      headers: key ? { Authorization: `Bearer ${key}` } : undefined,
      signal: AbortSignal.any([this.signal, signal, AbortSignal.timeout(10000)]),
    });
    if (!response.ok) throw new Error(`Local model discovery failed: HTTP ${response.status}`);
    const data = await response.json() as { models?: { name?: unknown }[]; data?: { id?: unknown }[] };
    const names = ollama ? data.models?.map(model => model.name) : data.data?.map(model => model.id);
    if (!Array.isArray(names)) throw new Error('Invalid local model response.');
    return [...new Set(names.filter((name): name is string => typeof name === 'string' && !!name.trim()))];
  }

  async installedAgents(): Promise<string[]> {
    const agents = await Promise.all(['codex', 'claude'].map(id =>
      detectLocalAgent(id, id === 'codex' ? this.configuration.get('codex').command : undefined, this.signal)));
    return agents.filter(agent => agent.installed).map(agent => agent.id);
  }

  getConfig(): LLMConfig {
    return { ...this.effective, fallbackChain: this.effective.fallbackChain?.map(entry => ({ ...entry })) };
  }

  updateSelection(): void {
    const primary = this.configuration.getLLMConfig();
    const local = this.configuration.getLLMConfig('local');
    this.effective = { ...primary, fallbackChain: [
      ...(primary.provider !== 'local' && local.model?.trim() ? [local] : []),
      { provider: 'deterministic', model: 'evidence-only' },
    ] };
  }

  description(): string {
    const state = this.readiness;
    if (!state) return 'Provider initialization pending';
    return `Primary ${state.configured.provider}/${state.configured.model}: ${state.primary.detail}; local: ${state.local.detail}; active ${state.active.provider}/${state.active.model}`;
  }

  track(backbone: LLMBackbone): void {
    const retain = () => this.localSession?.retain();
    backbone.on('request:start', () => { if (backbone.getProvider() === 'local') retain(); });
    backbone.on('request:fallback', event => { if (event.toProvider === 'local') retain(); });
  }

  async prepare(report?: ProgressReporter, checkSignal = this.signal, check: 'primary' | 'local' = 'primary'): Promise<string> {
    this.signal.throwIfAborted();
    const primary = { ...this.configuration.getLLMConfig(), fallbackChain: [] };
    const chosen = this.configuration.getLLMConfig('local');
    const local = chosen.model?.trim() ? { ...chosen, fallbackChain: [] } : undefined;
    if (this.localSession && (!local || this.localConfig?.model !== local.model || this.localConfig.baseUrl !== local.baseUrl)) await this.stop();
    if (local && !this.localSession) {
      this.localSession = createOllamaSession(local);
      this.localConfig = { model: local.model, baseUrl: local.baseUrl };
    }
    const deterministic = { provider: 'deterministic' as const, model: 'evidence-only' };
    this.effective = { ...primary, fallbackChain: [...(primary.provider !== 'local' && local ? [local] : []), deterministic] };
    const state: ProviderReadiness = {
      configured: { provider: primary.provider, model: primary.model },
      primary: { ready: false, detail: 'checked on first request' },
      local: { ready: false, model: local?.model, detail: local ? 'configured; loaded on first use' : 'not selected; discover or add a model in Settings' },
      active: { provider: primary.provider, model: primary.model },
    };
    this.readiness = state;
    const detail = (error: unknown) => String(redactSecrets(error instanceof Error ? error.message : String(error)));
    if (check === 'local') {
      if (!local) throw new Error('Select or manually add a local model in Settings.');
      this.localSession?.retain();
      await validateProvider(local, AbortSignal.any([this.signal, checkSignal]), undefined, report);
      state.local = { ready: true, model: local.model, detail: 'inference ready' };
      return `Local ${local.model}: inference ready. Primary ${primary.provider}/${primary.model} remains selected; it was not tested.`;
    }
    if (primary.provider === 'local') {
      if (!primary.model?.trim()) throw new Error('Select or manually add a local model in Settings.');
      report?.({ label: 'Local inference deferred until first use', status: 'skipped' });
    } else if (['mock', 'deterministic'].includes(primary.provider)) {
      this.effective = deterministic; state.active = deterministic;
      throw new Error('No AI inference provider selected.');
    } else {
      try {
        await validateProvider(primary, AbortSignal.any([this.signal, checkSignal]), this.configuration.get('codex').command, report);
        state.primary = { ready: true, detail: 'inference ready' };
      } catch (error) {
        this.signal.throwIfAborted();
        state.primary.detail = checkSignal.aborted ? 'check skipped; retried on first request' : detail(error);
        if (!checkSignal.aborted && !local) throw new Error(this.description());
        if (!checkSignal.aborted && local) report?.({ label: `Primary unavailable; ${local.model} fallback will be tried on first request`, status: 'skipped' });
      }
    }
    report?.({ label: `Using ${state.active.provider}/${state.active.model}`, status: 'completed' });
    return this.description();
  }

  async stop(): Promise<void> {
    const held = this.localSession;
    await held?.stop();
    if (this.localSession === held) { this.localSession = undefined; this.localConfig = undefined; }
  }

  async close(): Promise<void> {
    this.signal.removeEventListener('abort', this.abort);
    try { await this.stop(); }
    finally { await stopOwnedOllama(); }
  }
}

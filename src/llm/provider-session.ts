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
  private localSessions = new Map<string, ReturnType<typeof createOllamaSession>>();
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
      // Allow the on-demand daemon startup (30s) before the model-list request.
      signal: AbortSignal.any([this.signal, signal, AbortSignal.timeout(45000)]),
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
    return { ...this.effective, fallbackPolicy: this.effective.fallbackPolicy ? { ...this.effective.fallbackPolicy } : undefined,
      fallbackChain: this.effective.fallbackChain?.map(entry => ({ ...entry })) };
  }

  updateSelection(): void {
    this.effective = this.configuration.getLLMConfig();
  }

  description(): string {
    const state = this.readiness;
    if (!state) return 'Provider initialization pending';
    return `Primary ${state.configured.provider}/${state.configured.model}: ${state.primary.detail}; local: ${state.local.detail}; active ${state.active.provider}/${state.active.model}`;
  }

  track(backbone: LLMBackbone): void {
    backbone.on('request:provider', provider => {
      if (provider.provider === 'local') this.localSessionFor(provider).retain();
    });
  }

  private localSessionFor(local: LLMConfig): ReturnType<typeof createOllamaSession> {
    const key = JSON.stringify([local.model, local.baseUrl || 'http://127.0.0.1:11434/api']);
    let session = this.localSessions.get(key);
    if (!session) { session = createOllamaSession({ ...local, fallbackChain: [] }); this.localSessions.set(key, session); }
    return session;
  }

  async prepare(report?: ProgressReporter, checkSignal = this.signal, check: 'primary' | 'local' = 'primary'): Promise<string> {
    this.signal.throwIfAborted();
    this.updateSelection();
    const primary = { ...this.effective, fallbackChain: [] };
    const chosen = check === 'local' ? this.configuration.getLLMConfig('local')
      : primary.provider === 'local' ? primary
      : this.effective.fallbackChain?.find(entry => entry.provider === 'local') || this.configuration.getLLMConfig('local');
    const local = chosen.model?.trim() ? { ...chosen, fallbackChain: [] } : undefined;
    if (local) this.localSessionFor(local);
    const deterministic = { provider: 'deterministic' as const, model: 'evidence-only' };
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
      this.localSessionFor(local).retain();
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
        if (!checkSignal.aborted && (!this.effective.fallbackChain?.length || this.effective.fallbackPolicy?.enabled === false)) throw new Error(this.description());
        if (!checkSignal.aborted) report?.({ label: 'Primary unavailable; the first request will apply the configured fallback policy', status: 'skipped' });
      }
    }
    report?.({ label: `Using ${state.active.provider}/${state.active.model}`, status: 'completed' });
    return this.description();
  }

  async stop(): Promise<void> {
    const failures: unknown[] = [];
    // Reverse acquisition order restores the previous keep-alive environment.
    for (const [key, session] of [...this.localSessions].reverse()) {
      try { await session.stop(); this.localSessions.delete(key); }
      catch (error) { failures.push(error); }
    }
    if (failures.length) throw new AggregateError(failures, 'Could not release all local model sessions.');
  }

  async close(): Promise<void> {
    this.signal.removeEventListener('abort', this.abort);
    try { await this.stop(); }
    finally { await stopOwnedOllama(); }
  }
}

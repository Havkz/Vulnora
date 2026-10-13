import { mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { config as settings, ApiKeyProvider } from '../config/index.js';
import type { ProjectSession, ProjectLogEvent } from '../projects/session.js';
import type { ProjectStore, ProjectRecord, ProjectDraft, ScanningBehavior } from '../projects/store.js';
import { validateProjectName, validateProjectTarget } from '../projects/targets.js';
import type { LLMConfig } from '../types/index.js';
import { initializeTerminal, TerminalInterrupted, TerminalSurface, terminalText, wrapTerminalText } from './terminal.js';

type Configuration = typeof settings;
export interface InteractiveServices {
  configuration: Configuration;
  store: ProjectStore;
  open: (id: string, llm: LLMConfig) => Promise<ProjectSession>;
  llm: () => LLMConfig;
  installedModels: () => Promise<string[]>;
  prepareProviders: () => Promise<string>;
}

/** Screens share the real durable project/session services and one input owner. */
export class InteractiveApp {
  private session?: ProjectSession;
  private draft?: ProjectDraft;
  private issue = '';

  constructor(readonly surface: TerminalSurface, private services: InteractiveServices) {}

  async run(): Promise<void> {
    try {
      for (;;) {
        const choice = await this.surface.menu('VULNORA', ['Create New Project', 'Resume Project', 'Settings']);
        if (choice === undefined) return;
        try {
          if (choice === 0) await this.create();
          else if (choice === 1) await this.resume();
          else await this.settings();
        } catch (error) {
          if (error instanceof TerminalInterrupted) throw error;
          await this.notice('Unable to continue', error instanceof Error ? error.message : String(error));
        } finally { await this.closeSession(); }
      }
    } finally {
      if (this.draft) await this.services.store.saveDraft(this.draft);
      await this.closeSession();
      await this.services.store.flush();
    }
  }

  private async closeSession(): Promise<void> {
    const session = this.session; this.session = undefined;
    await session?.close();
  }

  private async notice(title: string, text: string): Promise<void> {
    await this.document(title, text, 'Enter Continue    Esc Back    Ctrl+C Save & Quit');
  }

  private async document(title: string, text: string, footer = '↑/↓ Scroll    PgUp/PgDn Page    Esc Back    Ctrl+C Save & Quit'): Promise<void> {
    let offset = 0;
    this.surface.show(() => {
      const lines = wrapTerminalText(text, this.surface.columns - 4);
      const room = Math.max(1, this.surface.rows - 5);
      offset = Math.max(0, Math.min(offset, Math.max(0, lines.length - room)));
      return { lines: [this.surface.colors.accent(terminalText(title)), '', ...lines.slice(offset, offset + room).map(line => '  ' + this.surface.colors.foreground(line))], footer };
    });
    for (;;) {
      const { key } = await this.surface.nextKey();
      if (key.name === 'escape' || key.name === 'return') return;
      if (key.name === 'up') offset--;
      if (key.name === 'down') offset++;
      if (key.name === 'pageup') offset -= Math.max(1, this.surface.rows - 5);
      if (key.name === 'pagedown') offset += Math.max(1, this.surface.rows - 5);
      if (key.name === 'home') offset = 0;
      if (key.name === 'end') offset = Number.MAX_SAFE_INTEGER;
      this.surface.refresh();
    }
  }

  private async create(existing?: ProjectDraft): Promise<void> {
    this.draft = existing;
    let name = existing?.name || '';
    for (;;) {
      if (!this.draft) {
        const answer = await this.surface.prompt('Project name:', name, false, value => { name = value; });
        if (answer === undefined) return;
        try { validateProjectName(answer); }
        catch (error) { await this.notice('Invalid project name', (error as Error).message); continue; }
        this.draft = await this.services.store.createDraft(answer, this.services.configuration.get('scanningBehavior'));
      }
      const draft = this.draft;
      const input = await this.surface.prompt('Target URL or IP:', draft.targetInput, false, value => { draft.targetInput = value; });
      draft.lastActivity = Date.now();
      await this.services.store.saveDraft(draft);
      if (input === undefined) return;
      try { validateProjectTarget(input); }
      catch (error) { await this.notice('Invalid target', (error as Error).message); continue; }
      const project = await this.services.store.finishDraft(draft);
      this.draft = undefined;
      await this.ready(project);
      return;
    }
  }

  private async ready(project: ProjectRecord): Promise<void> {
    for (;;) {
      this.surface.show(() => ({ lines: [...(this.surface.rows >= 12 ? [...this.surface.logo(), ''] : []),
        ...wrapTerminalText(`Target URL or IP: ${project.target.input}`, this.surface.columns - 4).map(line => '  ' + this.surface.colors.foreground(line)), '',
        '  ' + this.surface.colors.success('READY') + '  ' + this.surface.colors.muted('Press Enter to start')],
      footer: 'Enter Start    Esc Edit target    Ctrl+C Save & Quit' }));
      const { key } = await this.surface.nextKey();
      if (key.name === 'escape') {
        const answer = await this.surface.prompt('Target URL or IP:', project.inputDraft || project.target.input, false,
          value => { project.inputDraft = value; });
        await this.services.store.save(project);
        if (answer === undefined) return;
        try {
          project.target = validateProjectTarget(answer); project.inputDraft = undefined; project.checkpoint = undefined;
          await this.services.store.save(project);
        }
        catch (error) { await this.notice('Invalid target', (error as Error).message); }
      } else if (key.name === 'return') {
        this.session = await this.services.open(project.id, this.services.llm());
        await this.scan();
        return;
      }
    }
  }

  private async resume(): Promise<void> {
    const { projects, errors } = await this.services.store.list();
    const drafts = await this.services.store.listDrafts();
    if (errors.length || drafts.errors.length) await this.notice('Preserved project files requiring inspection', [...errors, ...drafts.errors].join('\n'));
    const entries: (ProjectRecord | ProjectDraft)[] = [...projects, ...drafts.drafts].sort((a, b) => b.lastActivity - a.lastActivity);
    if (!entries.length) { await this.notice('Resume Project', 'No saved projects. Create New Project to begin.'); return; }
    const selected = await this.surface.menu('Resume Project', entries.map(project => `${project.name} · ${'status' in project ? `${project.status} · ${project.progress}%` : 'Target pending'}`), index => {
      const project = entries[index];
      return [`Target: ${'target' in project ? project.target.input : project.targetInput || '(not entered)'}`,
        `Created: ${new Date(project.createdAt).toLocaleString()}`,
        `Last activity: ${new Date(project.lastActivity).toLocaleString()}`];
    });
    if (selected === undefined) return;
    const project = entries[selected];
    if (!('status' in project)) return this.create(project);
    if (project.status === 'ready') return this.ready(project);
    this.session = await this.services.open(project.id, this.services.llm());
    if (project.status === 'completed') await this.results();
    else {
      const choice = await this.surface.menu(`${project.name} · ${project.status}`, ['Resume', 'View saved logs']);
      if (choice === 0) await this.scan();
      else if (choice === 1) {
        const history = await this.services.store.readLogs(project.id);
        await this.document('Saved project logs', history.events.map(event => formatProjectLog(event as ProjectLogEvent)).join('\n\n'));
      }
    }
  }

  private async scan(): Promise<void> {
    const session = this.session;
    if (!session) throw new Error('No project is open.');
    const history = await this.services.store.readLogs(session.project.id);
    const logs = history.events.map(event => formatProjectLog(event as ProjectLogEvent));
    let tail = true; let offset = 0;
    this.issue = '';
    const onLog = (event: ProjectLogEvent) => { logs.push(formatProjectLog(event)); this.surface.refresh(); };
    const onError = (error: Error) => { this.issue = error.message; this.surface.refresh(); };
    session.on('log', onLog); session.on('error', onError);
    const render = () => {
      const header = [`${session.project.name} · ${session.project.status} · ${session.project.progress}%`,
        session.project.target.input, `Configured provider: ${session.command.llm.getProvider()} · ${session.command.llm.getModel()}`];
      const heading = header.flatMap(line => wrapTerminalText(line, this.surface.columns - 4));
      const lines = logs.flatMap(line => wrapTerminalText(line, this.surface.columns - 4));
      const completed = session.project.status === 'completed';
      const room = Math.max(1, this.surface.rows - heading.length - (completed || this.issue ? 7 : 5));
      offset = tail ? Math.max(0, lines.length - room) : Math.max(0, Math.min(offset, Math.max(0, lines.length - room)));
      return { lines: [...heading.map(line => '  ' + this.surface.colors.accent(line)), '',
        ...lines.slice(offset, offset + room).map(line => '  ' + this.surface.colors.foreground(line)), '',
        ...(this.issue ? wrapTerminalText(this.issue, this.surface.columns - 4).map(line => this.surface.colors.error(line)) : []),
        ...(completed ? [this.surface.colors.muted('Press Enter to view results')] : [])],
      footer: 'Esc Pause    Ctrl+C Save & Quit    PgUp/PgDn Logs    End Live' };
    };
    try {
      this.surface.show(render);
      await session.start();
      for (;;) {
        const { key } = await this.surface.nextKey();
        if (key.name === 'return' && session.project.status === 'completed') { await this.results(); return; }
        if (key.name === 'escape') {
          if (session.project.status === 'completed') return;
          this.surface.show(() => ({ lines: [this.surface.colors.active('Saving progress and stopping active work…')], footer: 'Ctrl+C Save & Quit' }));
          await session.pause();
          for (;;) {
            const choice = await this.surface.menu('Paused', ['Resume', 'Settings']);
            if (choice === undefined) return;
            if (choice === 0) { this.surface.show(render); await session.start(); break; }
            await this.settings();
          }
        }
        if (key.name === 'pageup' || key.name === 'up') { tail = false; offset -= key.name === 'up' ? 1 : this.surface.rows - 5; }
        if (key.name === 'pagedown' || key.name === 'down') { tail = false; offset += key.name === 'down' ? 1 : this.surface.rows - 5; }
        if (key.name === 'home') { tail = false; offset = 0; }
        if (key.name === 'end') tail = true;
        this.surface.refresh();
      }
    } finally { session.off('log', onLog); session.off('error', onError); }
  }

  private async results(): Promise<void> {
    const session = this.session;
    if (!session) throw new Error('No project is open.');
    const report = await session.results();
    const exported = await this.services.store.exportReport(session.project);
    await this.document(`${session.project.name} · Results`, `Saved report: ${exported}\n\n${report}`);
  }

  private async settings(): Promise<void> {
    const config = this.services.configuration;
    for (;;) {
      const choice = await this.surface.menu('Settings', ['Scanning Behavior', 'Change Default Model / Provider', 'Change API Key', 'Back']);
      if (choice === undefined || choice === 3) return;
      if (choice === 0) {
        const selected = await this.surface.menu('Scanning Behavior', ['Auto · adaptive', 'Stealth · low impact', 'Aggressive · bounded throughput']);
        if (selected !== undefined) {
          const behavior: ScanningBehavior = ['auto', 'stealth', 'aggressive'][selected] as ScanningBehavior;
          config.set('scanningBehavior', behavior);
          if (this.session) { this.session.project.behavior = behavior; await this.services.store.save(this.session.project); }
        }
      } else if (choice === 1) {
        const providers = ['codex', 'local-agent', 'local', 'openrouter', 'venice', 'anthropic', 'openai', 'xai', 'gemini', 'litellm', 'deepseek'] as const;
        const selected = await this.surface.menu('Provider', providers.map(provider => provider === 'local' ? 'Ollama / local' : provider === 'local-agent' ? 'Installed Codex / Claude CLI' : provider));
        if (selected === undefined) continue;
        const provider = providers[selected];
        let models: string[];
        if (provider === 'local') models = await this.services.installedModels();
        else if (provider === 'local-agent') models = ['codex', 'claude'];
        else models = (await import('../config/index.js')).AVAILABLE_MODELS[provider].map(model => model.id);
        if (!models.length) { await this.notice('Model unavailable', 'No installed models found. No model was downloaded.'); continue; }
        const model = await this.surface.menu('Default model', [...models, 'Enter model ID']);
        if (model === undefined) continue;
        const id = model < models.length ? models[model] : await this.surface.prompt('Model ID:');
        if (!id?.trim()) continue;
        if (provider === 'local' && !models.includes(id)) { await this.notice('Model unavailable', 'Select an installed model.'); continue; }
        config.setDefaultModel(provider, id); config.setDefaultProvider(provider);
        if (process.env.VULNORA_DEFAULT_PROVIDER && process.env.VULNORA_DEFAULT_PROVIDER !== provider) {
          await this.notice('Environment override', 'VULNORA_DEFAULT_PROVIDER overrides the saved selection for this process.');
        }
        await this.services.prepareProviders();
      } else {
        const providers: ApiKeyProvider[] = ['openrouter', 'venice', 'anthropic', 'openai', 'xai', 'gemini', 'litellm', 'deepseek', 'local'];
        const selected = await this.surface.menu('API key provider', providers);
        if (selected === undefined) continue;
        const key = await this.surface.prompt('API key:', '', true);
        if (key?.trim()) config.setApiKey(providers[selected], key.trim());
      }
      if (this.session) this.session.command.llm.updateConfig(this.services.llm());
    }
  }
}

export function formatProjectLog(event: ProjectLogEvent): string {
  const time = new Date(event.timestamp).toLocaleTimeString('de-DE', { hour12: false });
  if (event.data && typeof event.data === 'object' && 'detail' in event.data && typeof event.data.detail === 'string') {
    const { detail, ...metadata } = event.data;
    return `${time} ${event.category}\n${detail}\n${JSON.stringify(metadata, null, 2)}`;
  }
  return `${time} ${event.category}\n${typeof event.data === 'string' ? event.data : JSON.stringify(event.data, null, 2)}`;
}

/** Dynamic initialization keeps terminal ownership active while services load. */
export async function runInteractive(surface = new TerminalSurface()): Promise<void> {
  const controller = new AbortController();
  let configuration: Configuration | undefined;
  let store: ProjectStore | undefined;
  let open: InteractiveServices['open'] | undefined;
  let localModel: string | undefined;
  let localSession: ReturnType<typeof import('../llm/ollama-session.js').createOllamaSession> | undefined;
  const interrupt = () => { controller.abort(new TerminalInterrupted()); void localSession?.stop().catch(() => {}); };
  const signal = () => surface.interrupt();
  surface.on('interrupt', interrupt);
  process.on('SIGINT', signal); process.on('SIGTERM', signal);

  const installedModels = async (): Promise<string[]> => {
    if (!configuration) throw new Error('Configuration unavailable.');
    const local = configuration.getLLMConfig('local');
    const base = (local.baseUrl || '').replace(/\/$/, '');
    if (!base.endsWith('/api')) throw new Error('Installed model discovery requires an Ollama /api endpoint.');
    const response = await fetch(`${base}/tags`, { signal: AbortSignal.any([controller.signal, AbortSignal.timeout(10000)]) });
    if (!response.ok) throw new Error(`Ollama discovery failed: HTTP ${response.status}`);
    const data = await response.json() as { models?: { name?: unknown }[] };
    if (!Array.isArray(data.models)) throw new Error('Invalid Ollama model response.');
    return data.models.map(model => model.name).filter((name): name is string => typeof name === 'string' && !!name.trim());
  };
  const llm = (): LLMConfig => {
    if (!configuration) throw new Error('Configuration unavailable.');
    const primary = configuration.getLLMConfig();
    if (localModel && primary.provider === 'local') primary.model = localModel;
    if (localModel && primary.provider !== 'local') {
      const local = configuration.getLLMConfig('local', localModel);
      primary.fallbackChain = [{ provider: 'local', model: local.model, baseUrl: local.baseUrl, apiKey: local.apiKey }];
    }
    return primary;
  };
  const prepareProviders = async (): Promise<string> => {
    if (!configuration) throw new Error('Configuration unavailable.');
    await localSession?.stop(); localSession = undefined; localModel = undefined;
    const models = await installedModels();
    const chosen = configuration.getLLMConfig('local').model;
    localModel = models.includes(chosen) ? chosen : models.length === 1 ? models[0] : undefined;
    if (!localModel) throw new Error(models.length ? 'Choose an installed Ollama model in Settings.' : 'No installed Ollama model found.');
    const { createOllamaSession } = await import('../llm/ollama-session.js');
    localSession = createOllamaSession(configuration.getLLMConfig('local', localModel));
    controller.signal.throwIfAborted();
    await localSession.start();
    controller.signal.throwIfAborted();
    return `${localModel} loaded; provider credentials still require validation`;
  };
  try {
    const rows = await initializeTerminal(surface, [
      async () => {
        configuration = (await import('../config/index.js')).config;
        return configuration.getConfigPath();
      },
      async () => {
        const { Arsenal, BUILTIN_TOOLS, EXTERNAL_TOOLS } = await import('../arsenal/index.js');
        const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS); arsenal.registerMany(EXTERNAL_TOOLS);
        const ready = await arsenal.getReadyToolDefinitions();
        const { ProjectSession } = await import('../projects/session.js');
        open = (id, config) => {
          if (!store) throw new Error('Project environment unavailable.');
          return ProjectSession.open(store, id, { llm: config });
        };
        return `${ready.length} tools ready; ${arsenal.getToolDefinitions().length - ready.length} unavailable`;
      },
      prepareProviders,
      async () => {
        if (!configuration) throw new Error('Configuration unavailable.');
        const { ProjectStore } = await import('../projects/store.js');
        store = new ProjectStore(join(dirname(configuration.getConfigPath()), 'projects'));
        await mkdir(store.directory, { recursive: true, mode: 0o700 });
        const projects = await store.list(); const drafts = await store.listDrafts();
        if (projects.errors.length || drafts.errors.length) throw new Error([...projects.errors, ...drafts.errors].join('; '));
        return `${projects.projects.length} projects; ${drafts.drafts.length} drafts`;
      },
    ], controller.signal);
    if (!configuration || !store || !open) throw new Error('Required initialization failed; saved data is preserved.');
    if (rows.some(row => row.status === 'failed')) {
      surface.startup(rows, 'Enter Continue    Ctrl+C Save & Quit');
      await surface.nextKey();
    }
    await new InteractiveApp(surface, { configuration, store, open, llm, installedModels, prepareProviders }).run();
  } finally {
    try { await localSession?.stop(); }
    finally {
      surface.off('interrupt', interrupt); process.off('SIGINT', signal); process.off('SIGTERM', signal);
      surface.dispose();
    }
  }
}

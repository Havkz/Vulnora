import { mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { config as settings, ApiKeyProvider } from '../config/index.js';
import type { ProjectSession, ProjectLogEvent } from '../projects/session.js';
import type { ProjectStore, ProjectRecord, ProjectDraft, ScanningBehavior } from '../projects/store.js';
import { validateProjectName, validateProjectTarget } from '../projects/targets.js';
import type { LLMConfig } from '../types/index.js';
import { fitTerminalText, initializeTerminal, TerminalInterrupted, TerminalSurface, terminalText, wrapTerminalText } from './terminal.js';
import { formatProjectLog, formatSavedProjectLog, phaseLabel, projectActivity } from './project-log.js';
export { formatProjectLog, projectLogStyle } from './project-log.js';
import { formatTerminalReport } from '../terminal-report.js';
import wrapAnsi from 'wrap-ansi';
import { redactSecrets, redactString } from '../redact.js';

type Configuration = typeof settings;
export interface InteractiveServices {
  configuration: Configuration;
  store: ProjectStore;
  open: (id: string, llm: LLMConfig) => Promise<ProjectSession>;
  llm: () => LLMConfig;
  installedModels: () => Promise<string[]>;
  installedAgents?: () => Promise<string[]>;
  prepareProviders: () => Promise<string>;
}

/** Screens share the real durable project/session services and one input owner. */
export class InteractiveApp {
  private session?: ProjectSession;
  private draft?: ProjectDraft;
  private issue = '';
  private transcript = false;

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
    await this.document(title, text, 'Enter Continue    Esc Back    Ctrl+X Save & Quit');
  }

  private async document(title: string, text: string, footer = '↑/↓ Scroll    PgUp/PgDn Page    Esc Back    Ctrl+X Save & Quit', markdown = false): Promise<void> {
    let offset = 0;
    const safeText = terminalText(text);
    const content = markdown ? formatTerminalReport(safeText, this.surface.colors) : safeText;
    let width = 0; let lines: string[] = [];
    this.surface.show(() => {
      if (width !== this.surface.columns - 4) {
        width = this.surface.columns - 4;
        lines = wrapAnsi(content, Math.max(1, width), { hard: true, wordWrap: false, trim: false }).split('\n');
      }
      const room = Math.max(1, this.surface.rows - 5);
      offset = Math.max(0, Math.min(offset, Math.max(0, lines.length - room)));
      return { lines: [this.surface.colors.accent(fitTerminalText(title, this.surface.columns - 1)), '', ...lines.slice(offset, offset + room).map(line => '  ' + this.surface.colors.foreground(line))], footer };
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
    let offset = 0; let width = 0; let target: string[] = []; let room = 1;
    for (;;) {
      this.surface.show(() => {
        if (width !== this.surface.panelColumns) {
          width = this.surface.panelColumns;
          target = wrapTerminalText(`Target URL or IP: ${project.target.input}`, width);
        }
        const instruction = wrapAnsi('Press Enter to start', width, { hard: true, trim: true }).split('\n').map(line => this.surface.colors.muted(line));
        const status = width >= 26 ? [this.surface.colors.success('READY') + '  ' + instruction[0]]
          : [this.surface.colors.success('READY'), ...instruction];
        const logo = this.surface.logo().length + target.length + status.length + 2 <= this.surface.panelRows ? this.surface.logo() : [];
        room = Math.max(1, this.surface.panelRows - status.length - 1 - (logo.length ? logo.length + 1 : 0));
        offset = Math.max(0, Math.min(offset, Math.max(0, target.length - room)));
        return { lines: [...logo, ...(logo.length ? [''] : []), ...this.surface.panel([
          ...target.slice(offset, offset + room).map(line => this.surface.colors.foreground(line)), '', ...status])],
        footer: this.surface.columns < 60 ? 'Enter Start  Esc Edit' : 'Enter Start    Esc Edit    PgUp/PgDn Target    Ctrl+X Save & Quit' };
      });
      const { key } = await this.surface.nextKey();
      if (key.name === 'up' || key.name === 'pageup') offset -= key.name === 'up' ? 1 : room;
      if (key.name === 'down' || key.name === 'pagedown') offset += key.name === 'down' ? 1 : room;
      if (key.name === 'home') offset = 0;
      if (key.name === 'end') offset = Number.MAX_SAFE_INTEGER;
      if (key.name === 'escape') {
        let answer: string | undefined;
        try {
          answer = await this.surface.prompt('Target URL or IP:', project.inputDraft ?? project.target.input, false,
            value => { project.inputDraft = value; });
        } finally { await this.services.store.save(project); }
        if (answer === undefined) return;
        try {
          project.target = validateProjectTarget(answer); project.inputDraft = undefined; project.checkpoint = undefined;
          await this.services.store.save(project);
          width = 0;
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
    const selected = await this.surface.menu('Resume Project', entries.map(project => `${project.name} · ${'status' in project ? `${project.status} · ${project.progress.toFixed(1)}%` : 'Target pending'}`), index => {
      const project = entries[index];
      return [`Project: ${project.name}`, `Target: ${'target' in project ? project.target.input : project.targetInput || '(not entered)'}`,
        `Created: ${new Date(project.createdAt).toLocaleString()}`,
        `Last activity: ${new Date(project.lastActivity).toLocaleString()}`,
        `Status: ${'status' in project ? project.status : 'Target pending'}`,
        `Progress: ${('progress' in project ? project.progress : 0).toFixed(1)}%`];
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
        await this.document('Saved project logs', history.events.map(event => formatSavedProjectLog(event as ProjectLogEvent)).join('\n\n'));
      }
    }
  }

  private async scan(): Promise<void> {
    const session = this.session;
    if (!session) throw new Error('No project is open.');
    const history = await this.services.store.readLogs(session.project.id);
    const logs = history.events as ProjectLogEvent[];
    let tail = true; let offset = 0;
    let width = 0; let processed = 0;
    let wrapped: { text: string; event: number; character: number }[] = [];
    let reflowAnchor: typeof wrapped[number] | undefined;
    const results = new Map<number, ProjectLogEvent>();
    const resultEvents = new Set<number>();
    const pending = new Map<string, number>();
    const linkResult = (index: number): number | undefined => {
      const event = logs[index];
      if (!event.category.startsWith('execution:')) return;
      const data = event.data && typeof event.data === 'object' ? event.data as Record<string, unknown> : {};
      const key = String(data.id);
      if (event.category === 'execution:started') {
        pending.set(key, index);
      } else if (event.category === 'execution:completed') {
        const call = pending.get(key); pending.delete(key);
        if (call !== undefined) { results.set(call, event); resultEvents.add(index); return call; }
      }
      return undefined;
    };
    logs.forEach((_event, index) => linkResult(index));
    let activity = 'Working'; let activitySince = Date.now();
    let recoveryDetails = '';
    this.issue = '';
    const onLog = (event: ProjectLogEvent) => {
      logs.push(event);
      const changed = linkResult(logs.length - 1);
      if (changed !== undefined && changed < processed) {
        if (!tail) reflowAnchor = wrapped[offset];
        processed = changed; wrapped = wrapped.filter(line => line.event < changed);
      }
      const next = projectActivity(event);
      if (next && next !== activity) { activity = next; activitySince = Date.now(); }
      this.surface.refresh();
    };
    const onError = (error: Error) => {
      this.issue = redactString(error.message);
      recoveryDetails = this.issue;
      const last = logs.at(-1);
      const data = last?.category === 'recovery:blocked' && last.data && typeof last.data === 'object' ? last.data as Record<string, unknown> : {};
      if (typeof data.toolName === 'string') {
        recoveryDetails += `\n\nInterrupted tool: ${data.toolName}\nRecorded arguments:\n${JSON.stringify(redactSecrets(data.parameters), null, 2)}`;
      }
      recoveryDetails += '\n\nThe saved checkpoint is retained. Automatic replay was stopped. Esc returns to the main menu; Ctrl+X saves and quits.';
      if ((logs.at(-1)?.data as { error?: string } | undefined)?.error !== this.issue) {
        onLog({ timestamp: Date.now(), category: 'project:error', data: { error: this.issue } });
      } else this.surface.refresh();
    };
    session.on('log', onLog); session.on('error', onError);
    const render = () => {
      const active = session.command.llm.getActiveProvider();
      const dense = this.surface.rows < 18;
      const mission = session.command.mission.getActiveMission() || session.command.mission.getAllMissions().at(-1);
      const completed = session.project.status === 'completed';
      const blocked = !!this.issue && !session.command.isRunning();
      const header = [`Stage: ${completed ? 'Completed' : phaseLabel(mission?.currentPhase)}${blocked ? ' · Paused' : ''}`,
        dense ? `${session.project.status} · ${session.project.progress.toFixed(1)}% · ${session.project.name}` : `${session.project.name} · ${session.project.status} · ${session.project.progress.toFixed(1)}%`,
        session.project.target.input, `Provider: ${active.provider} · ${active.model}`];
      const bottom = [...(this.issue ? [this.surface.colors.error(fitTerminalText(this.issue, this.surface.panelColumns))] : []),
        ...(completed ? wrapAnsi('Press Enter to view results', this.surface.panelColumns, { hard: true, trim: true }).split('\n').map(line => this.surface.colors.muted(line)) : [])];
      const headroom = Math.max(1, this.surface.panelRows - bottom.length - (completed ? 0 : 1) - (dense ? 1 : 3));
      const fullHeading = header.flatMap(line => wrapTerminalText(line, this.surface.panelColumns));
      const heading = fullHeading.length <= headroom ? fullHeading :
        (headroom >= 3 ? header : [header[0], `${active.provider} · ${active.model}`]).slice(0, headroom)
          .map(line => fitTerminalText(line, this.surface.panelColumns));
      const resized = width !== this.surface.panelColumns;
      const anchor = resized && !tail ? wrapped[offset] : reflowAnchor;
      reflowAnchor = undefined;
      if (resized) { width = this.surface.panelColumns; processed = 0; wrapped = []; }
      for (; processed < logs.length; processed++) {
        if (resultEvents.has(processed)) continue;
        const formatted = formatProjectLog(logs[processed], this.transcript, this.surface.colors, width, results.get(processed));
        const clean = terminalText(formatted);
        let character = 0;
        for (const line of formatted ? wrapAnsi(formatted, width, { hard: true, wordWrap: false, trim: false }).split('\n') : []) {
          wrapped.push({ text: line, event: processed, character });
          character += terminalText(line).length;
          if (clean[character] === '\n') character++;
        }
      }
      if (anchor) {
        wrapped.forEach((line, index) => {
          if (line.event === anchor.event && line.character <= anchor.character) offset = index;
        });
      }
      const pausedLabel = this.surface.columns < 40 ? 'Paused · Enter Details' : 'Recovery paused · Enter Details · Esc Back';
      const status = completed ? [] : [this.surface.colors.muted(fitTerminalText(blocked ? pausedLabel : `${activity} · ${Math.floor((Date.now() - activitySince) / 1000)}s`, this.surface.panelColumns))];
      const room = Math.max(1, this.surface.panelRows - heading.length - bottom.length - status.length - (dense ? 0 : 2));
      offset = tail ? Math.max(0, wrapped.length - room) : Math.max(0, Math.min(offset, Math.max(0, wrapped.length - room)));
      return { lines: this.surface.panel([...heading.map((line, index) => index === 0 ? this.surface.colors.emphasis(this.surface.colors.border(line)) : this.surface.colors.foreground(line)), ...(dense ? [] : ['']),
        ...wrapped.slice(offset, offset + room).map(line => line.text), ...status, ...(dense ? [] : ['']), ...bottom]),
      footer: blocked ? this.surface.columns < 40 ? 'Enter Info Esc Back' : this.surface.columns < 60 ? 'Enter Details Esc Back ^X Quit' : 'Enter Recovery details    Esc Main menu    Ctrl+X Save & Quit'
        : this.surface.columns < 60 ? `Esc Pause ^X Quit ^T ${this.transcript ? 'Brief' : 'Full'}`
        : `Esc Pause  Ctrl+X Quit  Ctrl+T ${this.transcript ? 'Brief' : 'Full output'}  PgUp/PgDn Logs  End Live` };
    };
    try {
      this.surface.show(render);
      await session.start();
      for (;;) {
        const { key } = await this.surface.nextKey();
        if (key.ctrl && key.name === 't') { this.transcript = !this.transcript; processed = 0; wrapped = []; tail = true; }
        if (key.name === 'return' && this.issue && !session.command.isRunning()) {
          await this.document('Recovery paused', recoveryDetails);
          this.surface.show(render); continue;
        }
        if (key.name === 'return' && session.project.status === 'completed') { await this.results(); return; }
        if (key.name === 'escape') {
          if (session.project.status === 'completed') return;
          if (this.issue && !session.command.isRunning()) return;
          this.surface.show(() => ({ lines: [this.surface.colors.active('Saving progress and stopping active work…')], footer: 'Ctrl+X Save & Quit' }));
          await session.pause();
          for (;;) {
            const choice = await this.surface.menu('Paused', ['Resume', 'Settings', 'Beenden']);
            if (choice === undefined) return;
            if (choice === 0) { this.surface.show(render); await session.start(); break; }
            if (choice === 2) throw new TerminalInterrupted();
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
    await this.document(`${session.project.name} · Results`, `Saved report: ${exported}\n\n${report}`, undefined, true);
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
          if (this.session) await this.session.setScanningBehavior(behavior);
        }
      } else if (choice === 1) {
        const providers = ['codex', 'local-agent', 'local', 'openrouter', 'venice', 'anthropic', 'openai', 'xai', 'gemini', 'litellm', 'deepseek'] as const;
        const selected = await this.surface.menu('Provider', providers.map(provider => provider === 'local' ? 'Ollama / local' : provider === 'local-agent' ? 'Installed Codex / Claude CLI' : provider));
        if (selected === undefined) continue;
        const provider = providers[selected];
        let models: string[];
        if (provider === 'local') models = await this.services.installedModels();
        else if (provider === 'local-agent') models = await this.services.installedAgents?.() || [];
        else models = (await import('../config/index.js')).AVAILABLE_MODELS[provider].map(model => model.id);
        if (!models.length) { await this.notice('Model unavailable', 'No installed models found. No model was downloaded.'); continue; }
        const custom = provider !== 'local' && provider !== 'local-agent';
        const model = await this.surface.menu('Default model', [...models, ...(custom ? ['Enter model ID'] : [])]);
        if (model === undefined) continue;
        const id = model < models.length ? models[model] : await this.surface.prompt('Model ID:');
        if (!id?.trim()) continue;
        if (provider === 'local' && !models.includes(id)) { await this.notice('Model unavailable', 'Select an installed model.'); continue; }
        config.setDefaultModel(provider, id); config.setDefaultProvider(provider);
        await this.refreshProviders();
      } else {
        const providers: ApiKeyProvider[] = ['openrouter', 'venice', 'anthropic', 'openai', 'xai', 'gemini', 'litellm', 'deepseek', 'local'];
        const selected = await this.surface.menu('API key provider', providers);
        if (selected === undefined) continue;
        const key = await this.surface.prompt('API key:', '', true);
        if (key?.trim()) {
          config.setApiKey(providers[selected], key.trim());
          await this.refreshProviders();
        }
      }
    }
  }

  private async refreshProviders(): Promise<void> {
    try { await this.notice('Provider availability', await this.services.prepareProviders()); }
    finally { if (this.session) this.session.command.llm.updateConfig(this.services.llm()); }
  }
}

/** Dynamic initialization keeps terminal ownership active while services load. */
export async function runInteractive(surface = new TerminalSurface()): Promise<void> {
  const controller = new AbortController();
  let configuration: Configuration | undefined;
  let store: ProjectStore | undefined;
  let open: InteractiveServices['open'] | undefined;
  let providers: import('../llm/provider-session.js').ProviderSession | undefined;
  const interrupt = () => { controller.abort(new TerminalInterrupted()); };
  const signal = () => surface.interrupt();
  surface.on('interrupt', interrupt);
  process.on('SIGINT', signal); process.on('SIGTERM', signal);

  const llm = (): LLMConfig => {
    if (!providers) throw new Error('Provider environment unavailable.');
    return providers.getConfig();
  };
  const prepareProviders = async (): Promise<string> => {
    if (!providers) throw new Error('Provider environment unavailable.');
    return providers.prepare();
  };
  try {
    const rows = await initializeTerminal(surface, [
      async () => {
        configuration = (await import('../config/index.js')).config;
        const { ProviderSession } = await import('../llm/provider-session.js');
        providers = new ProviderSession(configuration, controller.signal);
        return configuration.getConfigPath();
      },
      async () => {
        const { Arsenal, BUILTIN_TOOLS, EXTERNAL_TOOLS } = await import('../arsenal/index.js');
        const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS); arsenal.registerMany(EXTERNAL_TOOLS);
        const ready = await arsenal.getReadyToolDefinitions();
        const { ProjectSession } = await import('../projects/session.js');
        open = async (id, config) => {
          if (!store) throw new Error('Project environment unavailable.');
          const session = await ProjectSession.open(store, id, { llm: config });
          try {
            await store.appendLog(id, { timestamp: Date.now(), category: 'provider:availability', data: providers?.readiness });
            return session;
          } catch (error) { await session.close(); throw error; }
        };
        return `${ready.length} tools ready; ${arsenal.getToolDefinitions().length - ready.length} unavailable`;
      },
      async report => {
        if (!providers) throw new Error('Provider environment unavailable.');
        return providers.prepare(report);
      },
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
      surface.startup(rows, 'Enter Continue    Ctrl+X Save & Quit');
      for (;;) { if ((await surface.nextKey()).key.name === 'return') break; }
    }
    const runtime = providers;
    if (!runtime) throw new Error('Provider environment unavailable.');
    await new InteractiveApp(surface, { configuration, store, open, llm, prepareProviders,
      installedModels: () => runtime.installedModels(), installedAgents: () => runtime.installedAgents() }).run();
  } finally {
    try { await providers?.close(); }
    finally {
      surface.off('interrupt', interrupt); process.off('SIGINT', signal); process.off('SIGTERM', signal);
      surface.dispose();
    }
  }
}

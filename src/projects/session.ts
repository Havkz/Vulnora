import { normalizeAssessmentRules } from './assessment.js';
import { EventEmitter } from 'eventemitter3';
import { VulnoraCommand } from '../index.js';
import type { VulnoraConfig } from '../types/index.js';
import { redactSecrets } from '../redact.js';
import { validateEngineCheckpoint, type EngineCheckpoint } from './engine-checkpoint.js';
import { acquireProjectLease } from './lease.js';
import { ProjectStore, type ProjectRecord } from './store.js';
import { evaluateCoverage } from '../orchestrator/coverage.js';

export interface ProjectLogEvent { timestamp: number; category: string; data: unknown }
interface SessionEvents { log: ProjectLogEvent; status: ProjectRecord; error: Error }

/** One exclusive project, its real scanner, and its durable event journal. */
export class ProjectSession extends EventEmitter<SessionEvents> {
  readonly command: VulnoraCommand;
  private closing?: Promise<void>;
  private fatalError?: Error;
  private workStartedAt?: number;

  get workDurationMs(): number { return (this.project.workDurationMs || 0) + (this.workStartedAt === undefined ? 0 : Date.now() - this.workStartedAt); }

  private saveWorkTime(running = false): void {
    const now = Date.now();
    if (this.workStartedAt !== undefined) this.project.workDurationMs = (this.project.workDurationMs || 0) + now - this.workStartedAt;
    this.workStartedAt = running ? now : undefined;
  }

  private constructor(readonly store: ProjectStore, readonly project: ProjectRecord,
    configuration: Omit<VulnoraConfig, 'name' | 'hooks'>, private release: () => Promise<void>) {
    super();
    this.command = new VulnoraCommand({ ...configuration, name: project.name, strictScope: true,
      scanningBehavior: project.behavior, assessment: normalizeAssessmentRules(project.assessment, project.target.input),
      hooks: { onStateCheckpoint: () => this.persist() } });
    try {
      for (const name of project.assessment?.excludedTools || []) {
        if (!this.command.arsenal.getTool(name)) throw new Error(`Unknown excluded tool: ${name}. Review the project assessment rules.`);
      }
      if (project.checkpoint !== undefined) this.command.restoreCheckpoint(project.checkpoint);
      else {
        this.command.targetEnv.addTarget({ name: project.target.hostname, type: 'web_application',
          zone: 'external', address: project.target.input.trim(), metadata: { originalInput: project.target.input } });
      }
      this.command.setScanningBehavior(project.behavior);
    } catch (error) { this.command.opsec.cleanup(); throw error; }

    this.command.on('command:started', () => { this.workStartedAt ??= Date.now(); });
    this.command.on('command:resumed', () => { this.workStartedAt ??= Date.now(); });
    this.command.on('command:paused', () => this.saveWorkTime());
    this.command.on('scan:progress', event => this.record('scan:progress', event));
    this.command.arsenal.on('tool:process', event => this.record(`execution:${event.type}`, event));
    this.command.on('orchestration:event', event => this.record('orchestration:event', event));
    this.command.on('detection:triggered', event => this.record('detection:triggered', event));
    this.command.on('approval:decision', event => this.record('approval:decision', event));
    this.command.on('mission:phase_changed', event => this.record('mission:phase_changed', event));
    this.command.on('abort:recommended', reason => this.record('abort:recommended', { reason }));
    this.command.on('recovery:blocked', ({ task, error }) => {
      this.project.status = 'paused';
      const call = task.checkpoint?.activeCall || (task.executionPlan ? { name: task.executionPlan.toolName, arguments: task.executionPlan.parameters } : undefined);
      this.record('recovery:blocked', { taskId: task.id, taskName: task.name, error: error.message, recoveryAction: error.name === 'ActiveTestingAuthorizationRequired' ? 'authorize' : 'retry', callId: task.checkpoint?.activeCall?.id, toolName: call?.name, parameters: call?.arguments });
      this.emit('error', error);
    });
    this.command.llm.on('request:fallback', event => this.record('provider:fallback', event));
    this.command.llm.on('request:start', () => this.record('provider:activity', { state: 'started' }));
    this.command.llm.on('request:end', () => this.record('provider:activity', { state: 'completed' }));
    this.command.llm.on('request:trace', ({ stage, ...event }) => this.record(`provider:${stage}`, event));
    this.command.llm.on('request:progress', event => this.record('provider:progress', event));
    this.command.llm.on('request:retry', ({ error, ...event }) => this.record('provider:retry', { ...event, error: error.message }));
    this.command.llm.on('request:error', ({ error }) => this.record('provider:error', { error: error.message }));
    this.command.on('command:stopped', () => {
      this.saveWorkTime();
      if (!this.closing && this.command.mission.getAllMissions().some(mission => mission.status === 'completed')) {
        this.project.status = 'completed';
        const mission = this.command.mission.getAllMissions().at(-1);
        this.record('project:completed', { projectId: project.id, phase: mission?.currentPhase, completionStatus: mission?.completionStatus });
      }
    });
  }

  static async open(store: ProjectStore, id: string, configuration: Omit<VulnoraConfig, 'name' | 'hooks'>): Promise<ProjectSession> {
    const release = await acquireProjectLease(store.directory, id);
    let session: ProjectSession | undefined;
    try {
      const project = await store.load(id);
      if (project.checkpoint !== undefined) validateEngineCheckpoint(project.checkpoint);
      const checkpoint = project.checkpoint as EngineCheckpoint | undefined;
      if (checkpoint && JSON.stringify(normalizeAssessmentRules(checkpoint.assessment)) !== JSON.stringify(normalizeAssessmentRules(project.assessment))) {
        throw new Error('Saved assessment rules do not match the project; no scan started.');
      }
      if (checkpoint && (checkpoint.targets.length !== 1 || checkpoint.targets[0].address !== project.target.input.trim())) {
        throw new Error('Saved scanner scope does not match the original project target; no scan started.');
      }
      session = new ProjectSession(store, project, { ...configuration, operators: {
        ...configuration.operators, maxConcurrent: checkpoint?.limits.maxOperators || configuration.operators?.maxConcurrent,
      } }, release);
      if (project.status === 'running') {
        project.status = 'interrupted';
        session.record('project:recovered', { reason: 'Previous process ended before completing the project.' });
      }
      await session.persist();
      return session;
    } catch (error) { session?.command.stop(); session?.command.opsec.cleanup(); await release(); throw error; }
  }

  private record(category: string, data: unknown): void {
    const event: ProjectLogEvent = { timestamp: Date.now(), category, data: redactSecrets(data) };
    this.emit('log', event);
    void this.store.appendLog(this.project.id, event).catch(cause => {
      if (this.fatalError) return;
      this.fatalError = cause instanceof Error ? cause : new Error(String(cause));
      this.command.pause();
      this.emit('error', this.fatalError);
    });
  }

  private async persist(): Promise<void> {
    if (this.fatalError) throw this.fatalError;
    this.saveWorkTime(this.workStartedAt !== undefined);
    this.project.checkpoint = this.command.exportCheckpoint();
    const mission = this.command.mission.getActiveMission() || this.command.mission.getAllMissions().at(-1);
    this.project.progress = mission?.progress || 0;
    if (mission?.status === 'completed' && mission.completionStatus !== 'COMPLETED') {
      const entries = this.command.targetEnv.getAllTargets().flatMap(target => Object.values(evaluateCoverage(target.address, this.command.arsenal.getOrchestrator().getEvidence(), true).entries));
      const completed = entries.filter(entry => ['completed', 'completed_negative', 'not_applicable'].includes(entry.status)).length;
      this.project.progress = Math.min(99.9, entries.length ? completed / entries.length * 100 : 0);
    }
    this.project.lastActivity = Date.now();
    await this.store.save(this.project);
    this.emit('status', this.project);
  }

  async start(): Promise<void> {
    if (this.closing) throw new Error('This project session is closed.');
    if (this.project.status === 'completed') throw new Error('This project is completed; open its saved results.');
    if (this.fatalError) throw this.fatalError;
    this.project.status = 'running';
    this.record('project:started', { target: this.project.target.input });
    await this.persist();
    this.command.resume();
    if (this.command.isRunning()) return;
    this.command.start();
  }

  async pause(): Promise<void> {
    if (this.project.status !== 'completed') this.project.status = 'paused';
    await this.command.pauseAndDrain();
    this.record('project:paused', { projectId: this.project.id });
    await this.persist();
  }

  async recover(taskId: string, callId?: string): Promise<void> {
    if (this.closing || this.project.status === 'completed' || this.command.isRunning()) throw new Error('Recovery requires an open, paused project.');
    if (this.fatalError) throw this.fatalError;
    await this.command.pauseAndDrain();
    this.command.retryReviewedTask(taskId, callId);
    this.record('recovery:reviewed', { taskId, callId });
    await this.persist();
    await this.start();
  }

  async authorizeActiveTesting(taskId: string): Promise<void> {
    if (this.closing || this.fatalError || this.command.isRunning()) throw new Error('Authorization requires an open, paused project.');
    await this.command.pauseAndDrain();
    this.command.authorizeActiveTask(taskId);
    this.record('project:authorization', { taskId, target: this.project.target.input, scope: 'active impact validation; existing scope and tool approval gates remain enforced' });
    await this.persist(); await this.start();
  }

  async continueIncomplete(): Promise<void> {
    if (this.closing || this.fatalError || this.project.status !== 'completed') throw new Error('Open a completed, incomplete assessment before continuing.');
    this.command.reopenIncompleteMission();
    if (this.project.report) this.record('report:superseded', this.project.report);
    delete this.project.report;
    this.project.status = 'paused';
    this.record('project:continued', { reason: 'Recover missing coverage while preserving completed checks and evidence.' });
    await this.persist();
  }

  async setScanningBehavior(behavior: ProjectRecord['behavior']): Promise<void> {
    if (this.project.status === 'running') throw new Error('Pause the project before changing scanning behavior.');
    this.command.setScanningBehavior(behavior);
    this.project.behavior = behavior;
    this.record('scan:behavior', { behavior });
    await this.persist();
  }

  /** Called only after the user chooses to view results. */
  async results(): Promise<string> {
    if (this.project.report) return this.project.report.markdown;
    if (this.project.status !== 'completed') throw new Error('This project has not completed.');
    const mission = this.command.mission.getAllMissions().at(-1);
    if (!mission) throw new Error('Completed project has no saved mission or report.');
    const data = this.command.generateStructuredReport(mission.id);
    const markdown = this.command.analysis.exportToMarkdown(data);
    this.project.report = { markdown, generatedAt: data.generatedAt, json: this.command.analysis.exportToJson(data) };
    this.record('report:generated', { generatedAt: this.project.report.generatedAt });
    await this.persist();
    return markdown;
  }

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closing = (async () => {
      try {
        await this.command.pauseAndDrain();
        if (this.project.status === 'running') this.project.status = 'paused';
        this.command.stop();
        this.record('project:closed', { status: this.project.status });
        await this.persist();
        await this.store.flush(this.project.id);
      } finally {
        this.command.stop(); this.command.opsec.cleanup();
        await this.release();
      }
    })();
    return this.closing;
  }
}

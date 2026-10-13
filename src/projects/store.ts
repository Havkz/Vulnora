import { mkdir, open, rename, readFile, readdir, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { validateProjectName, validateProjectTarget, type ProjectTarget } from './targets.js';

export const PROJECT_STATUSES = ['ready', 'running', 'paused', 'completed', 'interrupted', 'failed'] as const;
export type ProjectStatus = typeof PROJECT_STATUSES[number];
export type ScanningBehavior = 'auto' | 'stealth' | 'aggressive';

export interface ProjectRecord<Checkpoint = unknown> {
  version: 1;
  id: string;
  name: string;
  target: ProjectTarget;
  createdAt: number;
  lastActivity: number;
  status: ProjectStatus;
  progress: number;
  behavior: ScanningBehavior;
  checkpoint?: Checkpoint;
  report?: { markdown: string; generatedAt: number };
}

function validId(id: string): boolean { return /^[\da-f]{8}-(?:[\da-f]{4}-){3}[\da-f]{12}$/i.test(id); }

function validateRecord(value: unknown): asserts value is ProjectRecord {
  if (!value || typeof value !== 'object') throw new Error('Invalid project record.');
  const project = value as ProjectRecord;
  if (project.version !== 1) throw new Error('Unsupported project version; the original file has been preserved.');
  if (!validId(project.id) || typeof project.name !== 'string' || !project.target || typeof project.target.input !== 'string'
    || !PROJECT_STATUSES.includes(project.status) || !['auto', 'stealth', 'aggressive'].includes(project.behavior)
    || !Number.isFinite(project.createdAt) || !Number.isFinite(project.lastActivity)
    || !Number.isFinite(project.progress) || project.progress < 0 || project.progress > 100) throw new Error('Invalid project metadata.');
  validateProjectName(project.name);
  const validated = validateProjectTarget(project.target.input);
  if (validated.kind !== project.target.kind || validated.hostname !== project.target.hostname) throw new Error('Project target metadata does not match the original input.');
  if (project.report && (typeof project.report.markdown !== 'string' || !Number.isFinite(project.report.generatedAt))) throw new Error('Invalid saved report.');
}

/** Atomic JSON checkpoints and a separately flushed append-only log journal. */
export class ProjectStore {
  private writes = new Map<string, Promise<void>>();
  private journalsReady = new Set<string>();
  constructor(readonly directory: string) {}

  private path(id: string, suffix = '.json'): string {
    if (!validId(id)) throw new Error('Invalid project ID.');
    return join(this.directory, id + suffix);
  }

  async create(name: string, target: string, behavior: ScanningBehavior = 'auto'): Promise<ProjectRecord> {
    const project: ProjectRecord = {
      version: 1, id: randomUUID(), name: validateProjectName(name), target: validateProjectTarget(target),
      createdAt: Date.now(), lastActivity: Date.now(), status: 'ready', progress: 0, behavior,
    };
    await this.save(project);
    return project;
  }

  async save(project: ProjectRecord): Promise<void> {
    validateRecord(project);
    // Capture the checkpoint now, before a running operator mutates its next step.
    const data = JSON.stringify(project);
    await this.enqueue(project.id, async () => {
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
      const temporary = this.path(project.id, `.${randomUUID()}.tmp`);
      const handle = await open(temporary, 'wx', 0o600);
      try { await handle.writeFile(data, 'utf8'); await handle.sync(); }
      finally { await handle.close(); }
      try { await rename(temporary, this.path(project.id)); }
      finally { await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
    });
  }

  async load(id: string): Promise<ProjectRecord> {
    await this.flush(id);
    const project: unknown = JSON.parse(await readFile(this.path(id), 'utf8'));
    validateRecord(project);
    if (project.id !== id) throw new Error('Project ID does not match its file.');
    return project;
  }

  async list(): Promise<{ projects: ProjectRecord[]; errors: string[] }> {
    await this.flush();
    let files: string[];
    try { files = await readdir(this.directory); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { projects: [], errors: [] }; throw error; }
    const projects: ProjectRecord[] = []; const errors: string[] = [];
    for (const file of files) {
      if (!file.endsWith('.json') || !validId(file.slice(0, -5))) continue;
      try { projects.push(await this.load(file.slice(0, -5))); }
      catch (error) { errors.push(`${file}: ${error instanceof Error ? error.message : String(error)}`); }
    }
    projects.sort((a, b) => b.lastActivity - a.lastActivity);
    return { projects, errors };
  }

  async appendLog(id: string, event: unknown): Promise<void> {
    this.path(id);
    const line = JSON.stringify(event) + '\n';
    await this.enqueue(id, async () => {
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
      await this.prepareJournal(id);
      const handle = await open(this.path(id, '.logs.jsonl'), 'a', 0o600);
      try { await handle.writeFile(line, 'utf8'); await handle.sync(); } finally { await handle.close(); }
    });
  }

  async readLogs(id: string): Promise<{ events: unknown[]; interruptedTail: boolean }> {
    await this.flush(id);
    let content: string;
    try { content = await readFile(this.path(id, '.logs.jsonl'), 'utf8'); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { events: [], interruptedTail: false }; throw error; }
    const lines = content.split('\n'); const events: unknown[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i]) continue;
      try { events.push(JSON.parse(lines[i])); }
      catch { if (i !== lines.length - 1) throw new Error(`Corrupt log record ${i + 1}; original log preserved.`); return { events, interruptedTail: true }; }
    }
    return { events, interruptedTail: false };
  }

  async flush(id?: string): Promise<void> {
    if (id) await this.writes.get(id);
    else await Promise.all(this.writes.values());
  }

  private async prepareJournal(id: string): Promise<void> {
    if (this.journalsReady.has(id)) return;
    const path = this.path(id, '.logs.jsonl');
    let content: string;
    try { content = await readFile(path, 'utf8'); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      this.journalsReady.add(id);
      return;
    }
    if (content && !content.endsWith('\n')) {
      const boundary = content.lastIndexOf('\n') + 1;
      const tail = content.slice(boundary);
      let complete = false;
      try { JSON.parse(tail); complete = true; } catch { /* interrupted append */ }
      if (complete) {
        const handle = await open(path, 'a');
        try { await handle.writeFile('\n'); await handle.sync(); } finally { await handle.close(); }
      } else {
        // Preserve an interrupted fragment before allowing new records into the journal.
        const backup = await open(this.path(id, `.${randomUUID()}.interrupted-log`), 'wx', 0o600);
        try { await backup.writeFile(tail, 'utf8'); await backup.sync(); } finally { await backup.close(); }
        const handle = await open(path, 'r+');
        try { await handle.truncate(Buffer.byteLength(content.slice(0, boundary), 'utf8')); await handle.sync(); }
        finally { await handle.close(); }
      }
    }
    this.journalsReady.add(id);
  }

  private async enqueue(id: string, action: () => Promise<void>): Promise<void> {
    const pending = (this.writes.get(id) || Promise.resolve()).then(action);
    this.writes.set(id, pending);
    // A write failure poisons the queue until the caller handles it; never continue a scan after data loss.
    await pending;
  }
}

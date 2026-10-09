import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { appendFile, readFile } from 'fs/promises';
import type { EvidenceRecord } from './tool-orchestrator.js';

export interface EvidenceQuery {
  target?: string;
  toolName?: string;
  attemptId?: string;
  sourceToolCallId?: string;
}

export interface EvidenceStore {
  readonly backend: 'memory' | 'jsonl' | 'sqlite';
  append(record: EvidenceRecord): Promise<void>;
  query(query?: EvidenceQuery): Promise<EvidenceRecord[]>;
  load(): Promise<void>;
}

export class MemoryEvidenceStore implements EvidenceStore {
  readonly backend: EvidenceStore['backend'] = 'memory';
  protected readonly records: EvidenceRecord[] = [];
  async append(record: EvidenceRecord): Promise<void> { this.records.push(record); }
  async load(): Promise<void> { /* no persistence */ }
  async query(query: EvidenceQuery = {}): Promise<EvidenceRecord[]> {
    return this.records.filter(record =>
      (!query.target || record.target === query.target)
      && (!query.toolName || record.toolName === query.toolName)
      && (!query.attemptId || record.attemptId === query.attemptId)
      && (!query.sourceToolCallId || record.sourceToolCallId === query.sourceToolCallId)
    ).map(record => ({ ...record }));
  }
}

export class JsonlEvidenceStore extends MemoryEvidenceStore {
  override readonly backend: EvidenceStore['backend'] = 'jsonl';
  constructor(private readonly path: string) { super(); }
  override async load(): Promise<void> {
    try {
      const content = await readFile(this.path, 'utf8');
      for (const line of content.split(/\r?\n/).filter(Boolean)) {
        try { this.records.push(JSON.parse(line) as EvidenceRecord); } catch { /* retain valid records */ }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
  override async append(record: EvidenceRecord): Promise<void> {
    await super.append(record);
    await appendFile(this.path, `${JSON.stringify(record)}\n`, { encoding: 'utf8', mode: 0o600 });
  }
}

export function evidenceStoreFromEnvironment(): EvidenceStore {
  const backend = String(process.env.T3MP3ST_EVIDENCE_STORE || 'memory').toLowerCase();
  if (backend === 'jsonl') {
    return new JsonlEvidenceStore(process.env.T3MP3ST_EVIDENCE_JSONL_PATH || join(tmpdir(), 't3mp3st-evidence.jsonl'));
  }
  // SQLite is reserved by the interface but intentionally not required as a dependency.
  return new MemoryEvidenceStore();
}

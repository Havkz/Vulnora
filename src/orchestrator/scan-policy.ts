import { setTimeout as delay } from 'node:timers/promises';

export type ScanningBehavior = 'auto' | 'stealth' | 'aggressive';
export const SCAN_PRESETS = {
  stealth: { operators: 1, concurrency: 1, intervalMs: 1000, timeoutMs: 30_000, retries: 0, backoffMs: 5000 },
  auto: { operators: 3, concurrency: 2, intervalMs: 250, timeoutMs: 15_000, retries: 1, backoffMs: 2000 },
  aggressive: { operators: 6, concurrency: 4, intervalMs: 50, timeoutMs: 10_000, retries: 2, backoffMs: 1000 },
} as const;

interface HostState { nextStart: number; backoffUntil: number; penalty: number; stable: number; latencyMs: number }
export interface ScanPolicyCheckpoint { behavior: ScanningBehavior; hosts: [string, HostState][] }
const emptyHost = (): HostState => ({ nextStart: 0, backoffUntil: 0, penalty: 0, stable: 0, latencyMs: 0 });

/** Shared by all operators; mode changes retain server backoff and accumulated budgets. */
export class ScanPolicy {
  behavior?: ScanningBehavior;
  private hosts = new Map<string, HostState>();
  private active = new Map<string, number>();
  private external = new Set<string>();
  private starting = new Set<string>();

  setBehavior(behavior: ScanningBehavior): void {
    if (!Object.hasOwn(SCAN_PRESETS, behavior)) throw new Error('Invalid scanning behavior.');
    this.behavior = behavior;
  }

  private state(host: string): HostState {
    let state = this.hosts.get(host);
    if (!state) { state = emptyHost(); this.hosts.set(host, state); }
    return state;
  }

  limits(host: string) {
    const preset = SCAN_PRESETS[this.behavior || 'auto'];
    const state = this.state(host);
    const factor = 2 ** state.penalty;
    const configuredTimeout = Number(process.env.VULNORA_WEB_REQUEST_TIMEOUT_MS);
    const timeoutCeiling = Number.isFinite(configuredTimeout) && configuredTimeout > 0
      ? Math.max(5000, Math.min(60_000, configuredTimeout)) : 60_000;
    return {
      operators: Math.max(1, Math.floor(preset.operators / factor)),
      concurrency: Math.max(1, Math.floor(preset.concurrency / factor)),
      intervalMs: Math.min(8000, preset.intervalMs * factor),
      timeoutMs: Math.min(timeoutCeiling, Math.max(preset.timeoutMs, Math.ceil(state.latencyMs * 4))),
      retries: preset.retries,
      backoffMs: Math.min(60_000, preset.backoffMs * factor),
    };
  }

  observe(host: string, latencyMs: number, status?: number, retryAfter?: string | null): void {
    const state = this.state(host);
    state.latencyMs = state.latencyMs ? state.latencyMs * 0.75 + latencyMs * 0.25 : latencyMs;
    if (status === undefined || status === 429 || status >= 500 || latencyMs > this.limits(host).timeoutMs / 2) {
      state.penalty = Math.min(4, state.penalty + 1);
      state.stable = 0;
      const seconds = retryAfter && /^\d+(?:\.\d+)?$/.test(retryAfter) ? Number(retryAfter) * 1000 : 0;
      const date = retryAfter ? Date.parse(retryAfter) - Date.now() : 0;
      state.backoffUntil = Math.max(state.backoffUntil, Date.now() + Math.max(this.limits(host).backoffMs,
        Number.isFinite(date) ? date : 0, seconds));
    } else if (++state.stable >= 8) {
      state.penalty = Math.max(0, state.penalty - 1);
      state.stable = 0;
    }
  }

  private async acquire(host: string, signal?: AbortSignal, exclusive = false, reserveStart = true): Promise<() => void> {
    for (;;) {
      signal?.throwIfAborted();
      const state = this.state(host);
      const active = this.active.get(host) || 0;
      const wait = Math.max(state.nextStart, state.backoffUntil) - Date.now();
      if (wait <= 0 && !this.external.has(host) && (exclusive ? active === 0 : active < this.limits(host).concurrency)) {
        this.active.set(host, active + 1);
        if (exclusive) this.external.add(host);
        if (reserveStart) state.nextStart = Date.now() + this.limits(host).intervalMs;
        return () => {
          const remaining = (this.active.get(host) || 1) - 1;
          if (remaining) this.active.set(host, remaining); else this.active.delete(host);
          if (exclusive) this.external.delete(host);
        };
      }
      await delay(Math.min(100, Math.max(1, wait)), undefined, { signal });
    }
  }

  async runNetwork<T>(host: string, runner: () => Promise<T>, signal?: AbortSignal, exclusive = true): Promise<T> {
    if (!this.behavior) return runner();
    const release = await this.acquire(host, signal, exclusive);
    try { signal?.throwIfAborted(); return await runner(); } finally { release(); }
  }

  commandArgs(command: string, args: string[], host: string): string[] {
    if (!this.behavior) return args;
    const limits = this.limits(host);
    const rate = String(Math.max(1, Math.floor(1000 / limits.intervalMs)));
    const concurrency = String(limits.concurrency);
    const seconds = String(Math.ceil(limits.timeoutMs / 1000));
    const retries = String(limits.retries);
    const options: Record<string, string[]> = {
      nmap: ['-T3', '--max-rate', rate, '--max-parallelism', concurrency, '--scan-delay', `${limits.intervalMs}ms`, '--max-retries', retries],
      nuclei: ['-rl', rate, '-c', concurrency, '-bs', '1', '-pc', concurrency, '-prc', concurrency, '-timeout', seconds, '-retries', retries, '-duc'],
      ffuf: ['-rate', rate, '-t', concurrency, '-timeout', seconds, '-p', String(limits.intervalMs / 1000), '-sa', '-noninteractive'],
      sqlmap: [`--threads=${concurrency}`, `--delay=${limits.intervalMs / 1000}`, `--timeout=${seconds}`, `--retries=${retries}`],
      gobuster: ['--threads', concurrency, '--delay', `${limits.intervalMs}ms`, '--timeout', `${seconds}s`, '--retry-attempts', retries],
      feroxbuster: ['--threads', concurrency, '--scan-limit', '1', '--rate-limit', rate, '--timeout', seconds, '--auto-bail'],
      httpx: ['-threads', concurrency, '-rate-limit', rate, '-timeout', seconds, '-retries', retries],
      katana: ['-concurrency', concurrency, '-parallelism', '1', '-rate-limit', rate, '-timeout', seconds, '-retry', retries],
      // Naabu counts complete passes; zero restores its default instead of disabling retries.
      naabu: ['-c', concurrency, '-rate', rate, '-timeout', String(limits.timeoutMs), '-retries', String(limits.retries + 1)],
      dalfox: ['--workers', concurrency, '--delay', String(limits.intervalMs), '--rate-limit', rate, '--timeout', seconds,
        '--retries', retries, '--retry-delay', String(limits.backoffMs), '--waf-bypass', 'off'],
      nikto: ['-Pause', String(limits.intervalMs / 1000), '-timeout', seconds],
      dnsx: ['-threads', concurrency, '-rate-limit', rate, '-retry', retries],
      subfinder: ['-rate-limit', rate, '-timeout', seconds],
      whatweb: ['--max-threads', concurrency, '--wait', String(limits.intervalMs / 1000)],
      curl: ['--max-time', seconds, '--retry', '0'],
    };
    const flags = options[command];
    if (!flags) return args;
    const owned = new Set(flags.filter(flag => flag.startsWith('-')).map(flag => flag.split('=')[0]));
    if (command === 'nmap') ['--min-rate', '--min-parallelism', '--max-scan-delay', '--max-rate', '--max-parallelism', '--scan-delay', '--max-retries'].forEach(flag => owned.add(flag));
    const filtered: string[] = [];
    for (let index = 0; index < args.length; index++) {
      const name = args[index].split('=')[0];
      if (command === 'nmap' && /^-T[0-5]$/.test(name)) continue;
      if (owned.has(name)) {
        if (!args[index].includes('=') && args[index + 1] && !args[index + 1].startsWith('-')) index++;
      } else filtered.push(args[index]);
    }
    return [...filtered, ...flags];
  }

  async fetch(url: URL, init: RequestInit, beforeRequest: () => Promise<void>): Promise<Response> {
    if (!this.behavior) return globalThis.fetch(url, init);
    const host = url.hostname;
    const method = (init.method || 'GET').toUpperCase();
    const retrySafe = (method === 'GET' || method === 'HEAD') && (init.body === undefined || init.body === null);
    for (let attempt = 0; ; attempt++) {
      const release = await this.acquire(host, init.signal || undefined, false, false);
      let started = 0;
      let ownsStart = false;
      try {
        while (this.starting.has(host)) await delay(10, undefined, { signal: init.signal || undefined });
        this.starting.add(host); ownsStart = true;
        // A failed durable budget reservation must never be treated as a network retry.
        await beforeRequest();
        const state = this.state(host);
        for (let wait = Math.max(state.nextStart, state.backoffUntil) - Date.now(); wait > 0;
          wait = Math.max(state.nextStart, state.backoffUntil) - Date.now()) {
          await delay(wait, undefined, { signal: init.signal || undefined });
        }
        init.signal?.throwIfAborted();
        const signal = AbortSignal.any([AbortSignal.timeout(this.limits(host).timeoutMs), ...(init.signal ? [init.signal] : [])]);
        started = Date.now();
        state.nextStart = started + this.limits(host).intervalMs;
        const pendingResponse = globalThis.fetch(url, { ...init, signal });
        this.starting.delete(host); ownsStart = false;
        const response = await pendingResponse;
        const bytes: Uint8Array[] = [];
        let size = 0;
        if (response.body) {
          const reader = response.body.getReader();
          try {
            for (;;) {
              const chunk = await reader.read();
              if (chunk.done) break;
              size += chunk.value.byteLength;
              if (size > 16 * 1024 * 1024) throw new Error('Target response exceeds the 16 MiB safety limit.');
              bytes.push(chunk.value);
            }
          } catch (error) { await reader.cancel().catch(() => {}); throw error; }
          finally { reader.releaseLock(); }
        }
        this.observe(host, Date.now() - started, response.status, response.headers.get('retry-after'));
        if (retrySafe && [429, 502, 503, 504].includes(response.status) && attempt < this.limits(host).retries) continue;
        const buffered = new Response(size ? Buffer.concat(bytes, size) : null,
          { status: response.status, statusText: response.statusText, headers: response.headers });
        Object.defineProperty(buffered, 'url', { value: response.url });
        return buffered;
      } catch (error) {
        if (!started || init.signal?.aborted) throw error;
        this.observe(host, Date.now() - started);
        // Oversized bodies and validation errors are permanent; only transport failures retry.
        const transportFailure = error instanceof Error && ['TypeError', 'TimeoutError'].includes(error.name);
        if (!retrySafe || !transportFailure || attempt >= this.limits(host).retries) throw error;
      } finally { if (ownsStart) this.starting.delete(host); release(); }
    }
  }

  exportCheckpoint(): ScanPolicyCheckpoint | undefined {
    return this.behavior ? structuredClone({ behavior: this.behavior, hosts: [...this.hosts] }) : undefined;
  }

  static validateCheckpoint(value: unknown): asserts value is ScanPolicyCheckpoint {
    const saved = value as ScanPolicyCheckpoint;
    if (!saved || !Object.hasOwn(SCAN_PRESETS, saved.behavior) || !Array.isArray(saved.hosts)
      || !saved.hosts.every(entry => Array.isArray(entry) && entry.length === 2 && typeof entry[0] === 'string'
        && entry[1] && ['nextStart', 'backoffUntil', 'latencyMs'].every(key => Number.isFinite(entry[1][key as keyof HostState]) && entry[1][key as keyof HostState] >= 0)
        && Number.isInteger(entry[1].penalty) && entry[1].penalty >= 0 && entry[1].penalty <= 4
        && Number.isInteger(entry[1].stable) && entry[1].stable >= 0 && entry[1].stable < 8)) {
      throw new Error('Invalid saved scanning policy.');
    }
  }

  restoreCheckpoint(saved: ScanPolicyCheckpoint): void {
    ScanPolicy.validateCheckpoint(saved);
    if (this.active.size) throw new Error('Cannot restore an active scanning policy.');
    this.behavior = saved.behavior;
    this.hosts = new Map(structuredClone(saved.hosts));
  }
}

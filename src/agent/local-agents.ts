// =============================================================================
// LOCAL AGENT CONNECTORS — "bring your own already-authed agent"
// =============================================================================
// Detect + connect agent CLIs that already live, authenticated, on the operator's machine
// (Claude Code, Codex, Hermes) and drive them headlessly as vulnora operators.
//
// SECURITY POSTURE (important):
//   - We NEVER read, print, log, or transmit credential contents. Codex/Claude report their own
//     authentication through official CLI status commands; legacy Hermes uses artifact presence.
//   - We do NOT enter or store any key. The CLIs are already logged in by the user; we only invoke them.
//   - A "ping"/"dispatch" spawns the user's own CLI as a child process with a prompt and captures its
//     stdout (the model's reply to OUR prompt — not secrets). Everything is local + user-initiated.
// =============================================================================

import { execFile, execFileSync, spawn } from 'child_process';
import { accessSync, constants, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'fs';
import { homedir, tmpdir, userInfo } from 'os';
import { join, dirname, resolve } from 'path';
import { StringDecoder } from 'node:string_decoder';

// vulnora injects its OWN provider keys (from .env) into the server process. If we let those leak into
// a spawned CLI, the CLI uses vulnora's key instead of the user's native login → 401. The entire point
// of this feature is "use the agent you already authed", so we strip these before spawning so each CLI
// falls back to its own auth (keychain / ~/.codex/auth.json / ~/.hermes/.env).
const PROVIDER_ENV_TO_STRIP = [
  'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_MODEL',
  'OPENAI_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_API_BASE', 'OPENAI_ORGANIZATION',
  'OPENROUTER_API_KEY',
];

/**
 * The REAL user home where the agent CLIs keep their own auth artifacts
 * (~/.claude.json, ~/.codex/auth.json, ~/.hermes/.env, macOS keychain).
 *
 * DELIBERATELY separate from os.homedir()/$HOME: VULNORA may run with HOME redirected
 * (e.g. an isolated app-config dir), and os.homedir() returns that redirected path. Detecting
 * OR spawning the user's CLIs against a redirected HOME makes an installed-and-authed agent
 * look unavailable — the Settings checkboxes go dead and it reads like a UI bug. Resolution
 * order:
 *   1. VULNORA_AGENT_HOME    — explicit override (a launcher that redirects HOME sets this).
 *   2. os.userInfo().homedir — the real home from the OS user DB (getpwuid), NOT affected by a
 *                              $HOME redirect, so this AUTO-recovers the correct home with no config.
 *   3. os.homedir()          — last-resort fallback.
 * os.homedir()/$HOME is intentionally left untouched for app-config storage (src/config reads it).
 */
export function agentHome(): string {
  const override = (process.env.VULNORA_AGENT_HOME || '').trim();
  if (override) return override;
  try {
    const real = userInfo().homedir;
    if (real) return real;
  } catch { /* userInfo can throw in some sandboxes — fall through to homedir() */ }
  return homedir();
}
const expand = (p: string): string => (p.startsWith('~') ? agentHome() + p.slice(1) : p);

/**
 * Resolve a path under the OS-native per-user local app-data root, cross-platform:
 *   - Windows: %LOCALAPPDATA% (e.g. C:\Users\<u>\AppData\Local), where the Hermes desktop app
 *     stores its runtime auth under %LOCALAPPDATA%\hermes\ rather than ~/.hermes/.
 *   - POSIX:   <agentHome>/AppData/Local fallback (harmless: the artifact simply won't exist there).
 * PRESENCE-ONLY: callers pass the result to existsSync(); contents are never read.
 */
const localAppData = (rel: string): string =>
  join(process.env.LOCALAPPDATA || join(agentHome(), 'AppData', 'Local'), ...rel.split('/'));

/**
 * Env for a spawned agent CLI. Two adjustments to our own env:
 *   - strip the injected provider keys so the CLI falls back to its OWN native login (not vulnora's).
 *   - point HOME (and USERPROFILE on Windows) at the agentHome() so the CLI finds that login even
 *     when vulnora itself runs with HOME redirected for app-config storage. Same home the detector
 *     used, so "detected as authed" and "actually authenticates when spawned" stay consistent.
 */
function childEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const k of PROVIDER_ENV_TO_STRIP) delete env[k];
  const home = agentHome();
  env.HOME = home;
  if (process.platform === 'win32') env.USERPROFILE = home;
  return env;
}

export type LocalAgentId = 'claude' | 'codex' | 'hermes';

/** Apply an authoritative bulk selection; single-agent connects remain additive. */
export function syncLocalAgentSelection<T>(
  connected: Map<string, T>,
  selectedIds: string[],
  replace: boolean,
): void {
  if (!replace) return;
  const selected = new Set(selectedIds);
  for (const id of connected.keys()) {
    if (!selected.has(id)) connected.delete(id);
  }
}

interface AgentSpec {
  id: LocalAgentId;
  label: string;
  vendor: string;
  bin: string;
  blurb: string;
  /** how we drive it as a one-shot, non-interactive operator */
  invokeHint: string;
  versionArgs: string[];
  parseVersion: (out: string) => string;
  /** any-of: presence ⇒ authed. PRESENCE ONLY — contents are never read. */
  authArtifacts: string[];
  /** macOS keychain fallback service name */
  keychainService?: string;
  /** build the argv for a headless one-shot prompt */
  oneShot: (prompt: string, model?: string) => string[];
}

const SPECS: AgentSpec[] = [
  {
    id: 'claude',
    label: 'Claude Code',
    vendor: 'Anthropic',
    bin: 'claude',
    blurb: 'Anthropic agentic CLI',
    invokeHint: 'claude -p "<prompt>"',
    versionArgs: ['--version'],
    parseVersion: (o) => (o.match(/[\d]+\.[\d]+(\.[\d]+)?/) || ['?'])[0],
    authArtifacts: ['~/.claude/.credentials.json', '~/.claude.json'],
    keychainService: 'Claude Code-credentials',
    oneShot: (p, m) => ['-p', p, '--output-format', 'text', ...(m ? ['--model', m] : [])],
  },
  {
    id: 'codex',
    label: 'Codex',
    vendor: 'OpenAI',
    bin: 'codex',
    blurb: 'OpenAI Codex CLI',
    invokeHint: 'codex exec "<prompt>"',
    versionArgs: ['--version'],
    parseVersion: (o) => (o.match(/[\d]+\.[\d]+(\.[\d]+)?/) || ['?'])[0],
    authArtifacts: ['~/.codex/auth.json', '~/.config/codex/auth.json'],
    oneShot: (p, m) => [
      'exec',
      '--ephemeral',
      '--skip-git-repo-check',
      '--sandbox',
      'read-only',
      '--color',
      'never',
      ...(m ? ['-m', m] : []),
      p,
    ],
  },
  {
    id: 'hermes',
    label: 'Hermes',
    vendor: 'Hermes Agent',
    bin: 'hermes',
    blurb: 'Hermes Agent — tool-calling AI',
    invokeHint: 'hermes -z "<prompt>"  (--yolo only if VULNORA_HERMES_YOLO=1)',
    versionArgs: ['--version'],
    parseVersion: (o) => (o.match(/v([\d]+\.[\d]+(\.[\d]+)?)/)?.[1]) || (o.match(/[\d]+\.[\d]+(\.[\d]+)?/) || ['?'])[0],
    // Hermes desktop on Windows stores its login under %LOCALAPPDATA%\hermes\ (NOT ~/.hermes/), so
    // checking only ~/.hermes/ made an authed Windows install read as NOT AUTHED. Presence-only check;
    // ~/.hermes/auth.json is upstream's POSIX/mac auth artifact, kept alongside the Windows paths.
    authArtifacts: ['~/.hermes/.env', "~/.hermes/auth.json", localAppData('hermes/.env'), localAppData('hermes/auth.json')],
    oneShot: (p, m) => ['-z', p, ...(hermesYoloEnabled() ? ['--yolo'] : []), ...(m ? ['-m', m] : [])],
  },
];

export function getSpec(id: string): AgentSpec | undefined {
  return SPECS.find((s) => s.id === id);
}

/**
 * B-06 — Hermes '--yolo' auto-approves EVERY tool call with no confirmation:
 * powerful but dangerous (unattended command exec with no gate). It is OFF by
 * default; the operator must explicitly opt in with VULNORA_HERMES_YOLO=1. Safe
 * mode (the default) runs Hermes without the flag so it honors its own approval
 * prompts. Applies to both the one-shot backbone call and the chat path.
 */
export function hermesYoloEnabled(): boolean {
  return /^(1|true|yes|on)$/i.test((process.env.VULNORA_HERMES_YOLO || '').trim());
}

export interface AgentDetection {
  id: LocalAgentId;
  label: string;
  vendor: string;
  bin: string;
  blurb: string;
  invokeHint: string;
  installed: boolean;
  path?: string;
  version?: string;
  authed: boolean;
  authMethod?: string; // e.g. "file" or "keychain" — never the secret itself
  ready: boolean;      // installed && authed
}

const isWin32 = (): boolean => process.platform === 'win32';
// Kept as a constructed RegExp so the source never embeds a raw CRLF inside a regex literal.
const NEWLINE_RE = new RegExp('\\r?\\n');

/**
 * Curated POSIX install dirs an agent CLI commonly lands in, under the REAL agent home (issue #78).
 *
 * The bug: a VULNORA server launched from Finder / the desktop app / any non-interactive shell
 * inherits launchd's minimal PATH (/usr/bin:/bin:/usr/sbin:/sbin). That omits every place a CLI
 * actually installs — so `execFile('claude', …)` throws ENOENT and a working, authed CLI reads as
 * `installed:false`. We recover it by ALSO scanning these dirs (they are where Claude Code's native
 * installer, Homebrew, npm-global, and the version managers put their bins). Anchored to agentHome()
 * — NOT os.homedir() — so a HOME redirect can't hide them (same rationale as `agentHome`).
 */
function wellKnownBinDirs(home: string): string[] {
  const dirs = [
    join(home, '.local', 'bin'),                       // Claude Code native installer, pipx, mise
    join(home, '.local', 'share', 'mise', 'shims'),    // mise
    join(home, '.asdf', 'shims'),                      // asdf
    '/opt/homebrew/bin',                               // Homebrew (Apple Silicon)
    '/usr/local/bin',                                  // Homebrew (Intel) / manual installs
    join(home, '.bun', 'bin'),                         // bun
    join(home, '.deno', 'bin'),                        // deno
    join(home, '.volta', 'bin'),                       // volta
    join(home, '.npm-global', 'bin'),                  // npm prefix override
    join(home, '.yarn', 'bin'),                        // yarn global
    join(home, 'Library', 'pnpm'),                     // pnpm (macOS default)
    join(home, '.local', 'share', 'pnpm'),             // pnpm (XDG)
    '/opt/local/bin',                                  // MacPorts
  ];
  // Version managers keep a per-version bin dir — enumerate the installed versions so an
  // npm-global CLI (e.g. codex) under the active node still resolves under a minimal PATH.
  for (const nodeVersions of [join(home, '.nvm', 'versions', 'node')]) {
    try { for (const v of readdirSync(nodeVersions)) dirs.push(join(nodeVersions, v, 'bin')); } catch { /* not present */ }
  }
  for (const fnmDir of [join(home, '.local', 'share', 'fnm', 'node-versions'),
                        join(home, 'Library', 'Application Support', 'fnm', 'node-versions')]) {
    try { for (const v of readdirSync(fnmDir)) dirs.push(join(fnmDir, v, 'installation', 'bin')); } catch { /* not present */ }
  }
  return dirs;
}

/**
 * Absolute path to `bin`, resolved WITHOUT an operator-controlled shell:
 *   - Windows: where.exe honors PATHEXT, preferring .exe > .cmd > .bat > first hit.
 *   - POSIX: PATH plus well-known install dirs under agentHome() (issue #78).
 *
 * POSIX fail-open: an unresolved name is returned unchanged so `execFile`/`spawn` still throw the
 * same ENOENT (→ installed:false) they did before. Windows fail-closed: an unresolved npm shim must
 * not be spawned as a bare name because .cmd/.bat launches need explicit shell handling.
 */
export function resolveBin(bin: string): string | undefined {
  // The Windows launcher shares the installed CLI, never its credential files.
  if (bin === 'codex' && process.platform === 'linux' && process.env.WSL_DISTRO_NAME && process.env.VULNORA_CODEX_HOST_COMMAND) {
    const host = process.env.VULNORA_CODEX_HOST_COMMAND;
    if (!host.startsWith('/mnt/') || !host.endsWith('.exe')) return undefined;
    return host;
  }
  if (isWin32()) {
    if (bin.includes('/') || bin.includes('\\')) {
      try { return statSync(bin).isFile() ? resolve(bin) : undefined; } catch { return undefined; }
    }
    try {
      const out = execFileSync('where.exe', [bin], { encoding: 'utf8', timeout: 5000, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
      const hits = out.split(NEWLINE_RE).map((h) => h.trim()).filter(Boolean);
      return (
        hits.find((h) => /\.exe$/i.test(h)) ??
        hits.find((h) => /\.cmd$/i.test(h)) ??
        hits.find((h) => /\.bat$/i.test(h)) ??
        hits[0]
      );
    } catch { return undefined; }
  }
  if (bin.includes('/')) return bin;
  const path = process.env.PATH || '';
  const native = wellKnownBinDirs(agentHome());
  // WSL inherits Windows npm shims; prefer the installed Linux CLI just as the launcher does.
  const directories = process.env.WSL_DISTRO_NAME || process.env.WSL_INTEROP
    ? [...native, ...path.split(':')] : [...path.split(':'), ...native];
  for (const dir of directories) {
    // Absolute dirs only: skips blank PATH segments (whose POSIX "= cwd" meaning is a known
    // CWD-execution vector) and relative segments (which would leak a non-absolute `path`).
    if (!dir.startsWith('/')) continue;
    const cand = join(dir, bin);
    try {
      // X_OK alone also passes for a DIRECTORY named `bin` (dirs carry the search bit); the OS's own
      // execvp skips such a directory and searches on, so require a regular file to match that and
      // avoid returning a dir that execFile would then reject with EACCES (a false installed:true).
      accessSync(cand, constants.X_OK);
      if (statSync(cand).isFile()) return cand;
    } catch { /* missing, not executable, or not a regular file — keep scanning */ }
  }
  return bin;
}

/** Launch npm's Windows agent shims through Node so prompts never enter cmd.exe. */
function agentCommand(binary: string, args: string[]): { command: string; args: string[] } {
  if (process.platform === 'linux' && process.env.WSL_DISTRO_NAME && binary === process.env.VULNORA_CODEX_HOST_COMMAND) {
    return { command: binary, args: args.map((arg, index) => ['-C', '--cd', '--output-last-message'].includes(args[index - 1])
      ? execFileSync('wslpath', ['-w', arg], { encoding: 'utf8', timeout: 5000 }).trim() : arg) };
  }
  if (!isWin32() || !/\.(cmd|bat)$/i.test(binary)) return { command: binary, args };
  const shim = readFileSync(binary, 'utf8');
  const script = shim.match(/"%dp0%[\\/]([^"\r\n]+\.(?:cjs|mjs|js))"/i)?.[1];
  if (!script || !/node\.exe|_prog=node/i.test(shim)) {
    throw new Error(`Unsupported Windows agent shim: ${binary}. Use a native executable or a standard npm Node shim.`);
  }
  return { command: process.execPath, args: [resolve(dirname(binary), script), ...args] };
}

export function spawnAgent(resolvedBin: string, args: string[], options: import('child_process').SpawnOptions): import('child_process').ChildProcess {
  const invocation = agentCommand(resolvedBin, args);
  return spawn(invocation.command, invocation.args, { windowsHide: true, ...options, shell: false });
}

async function authState(spec: AgentSpec, executable: string, signal?: AbortSignal): Promise<{ authed: boolean; method?: string }> {
  if (spec.id === 'codex' || spec.id === 'claude') {
    const args = spec.id === 'codex' ? ['login', 'status'] : ['auth', 'status'];
    return new Promise(resolve => {
      try {
        const invocation = agentCommand(executable, args);
        const child = execFile(invocation.command, invocation.args, { env: childEnv(), signal, timeout: 8000, maxBuffer: 65536, windowsHide: true, shell: false }, (error, stdout) => {
          if (error) { resolve({ authed: false }); return; }
          if (spec.id === 'codex') { resolve({ authed: true, method: 'cli_status' }); return; }
          try {
            const status = JSON.parse(String(stdout)) as { loggedIn?: boolean };
            resolve({ authed: status.loggedIn === true, method: 'cli_status' });
          } catch { resolve({ authed: false }); }
        });
        child.stdin?.end();
      } catch { resolve({ authed: false }); }
    });
  }
  for (const a of spec.authArtifacts) {
    if (existsSync(expand(a))) return { authed: true, method: 'file' };
  }
  if (spec.keychainService) {
    try {
      // timeout: a headless/SSH/locked-keychain session (the same non-interactive launch context
      // as #78) can make `security` block on an ACL prompt; bound it so detection can't hang the
      // event loop. A timeout throws → treated as "not in keychain" (fail-open, same as absence).
      execFileSync('security', ['find-generic-password', '-s', spec.keychainService], { stdio: 'ignore', timeout: 2000 });
      return { authed: true, method: 'keychain' };
    } catch { /* not in keychain */ }
  }
  return { authed: false };
}

function detectOne(spec: AgentSpec, signal?: AbortSignal): Promise<AgentDetection> {
  const base = {
    id: spec.id, label: spec.label, vendor: spec.vendor, bin: spec.bin,
    blurb: spec.blurb, invokeHint: spec.invokeHint,
  };
  // POSIX falls back to the bare name when unresolved; Windows keeps `resolved` authoritative because
  // bare npm .cmd/.bat shims require explicit shell handling after where.exe resolution.
  const exe = resolveBin(spec.bin) || (isWin32() ? undefined : spec.bin);
  return new Promise((resolve) => {
    if (!exe) {
      resolve({ ...base, installed: false, authed: false, ready: false });
      return;
    }
    const installedNoVersion = () => {
      resolve({
        ...base, installed: true, path: exe, version: '?',
        authed: false, ready: false,
      });
    };
    try {
      const invocation = agentCommand(exe, spec.versionArgs);
      const child = execFile(invocation.command, invocation.args, { env: childEnv(), signal, timeout: 8000, windowsHide: true, shell: false }, async (err, stdout) => {
        if (err && (err as NodeJS.ErrnoException).code === 'ENOENT') {
          resolve({ ...base, installed: false, authed: false, ready: false });
          return;
        }
        // even a non-zero exit but no ENOENT means the binary exists
        const version = spec.parseVersion(String(stdout || ''));
        const auth = !err && version !== '?' ? await authState(spec, exe, signal) : { authed: false };
        resolve({
          ...base,
          installed: true,
          path: exe,
          version,
          authed: auth.authed,
          authMethod: auth.method,
          ready: auth.authed,
        });
      });
      child.stdin?.end();
    } catch {
      // Synchronous spawn failures (for example restricted child-process creation) should not reject
      // the whole detection batch; the binary exists, but its version could not be probed.
      if (isWin32() && /\.(cmd|bat)$/i.test(exe)) resolve({ ...base, installed: false, authed: false, ready: false });
      else installedNoVersion();
    }
  });
}

/** Detect every known local agent CLI (installed? authed? ready?). No tokens spent. */
export function detectLocalAgent(id: string, command?: string, signal?: AbortSignal): Promise<AgentDetection> {
  const spec = getSpec(id);
  if (!spec) return Promise.reject(new Error(`Unknown local agent: ${id}`));
  return detectOne(command ? { ...spec, bin: command } : spec, signal);
}

export async function detectLocalAgents(): Promise<AgentDetection[]> {
  // Test/CI hook: VULNORA_DISABLE_LOCAL_AGENTS=1 forces a backbone-less server (skip
  // local-agent auto-detection) so key-required / fail-closed paths can be exercised
  // deterministically — used by scripts/arsenal-smoke.mjs for a reproducible run.
  if (/^(1|true|yes|on)$/i.test((process.env.VULNORA_DISABLE_LOCAL_AGENTS || '').trim())) return [];
  const settled = await Promise.allSettled(SPECS.map(spec => detectOne(spec)));
  return settled.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    const s = SPECS[i];
    return {
      id: s.id, label: s.label, vendor: s.vendor, bin: s.bin, blurb: s.blurb,
      invokeHint: s.invokeHint, installed: false, authed: false, ready: false,
    };
  });
}

export interface AgentRunResult {
  ok: boolean;
  latencyMs: number;
  output: string;
  error?: string;
}

function agentFailureOutput(output: string): string | null {
  const text = output.trim();
  if (/^API call failed\b/i.test(text)) return text.slice(0, 300);
  if (/connection error/i.test(text) && /failed/i.test(text)) return text.slice(0, 300);
  return null;
}

function envTimeoutMs(name: string, fallback: number): number {
  const parsed = Number(process.env[name]);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Drive a connected agent with a one-shot headless prompt (real round-trip — SPENDS the agent's quota).
 * Used by /ping (liveness proof) and /dispatch (actually using the operator).
 */
export function runLocalAgent(
  id: string,
  prompt: string,
  opts: { model?: string; timeoutMs?: number; maxChars?: number } = {},
): Promise<AgentRunResult> {
  const spec = getSpec(id);
  const t0 = Date.now();
  if (!spec) return Promise.resolve({ ok: false, latencyMs: 0, output: '', error: `unknown agent: ${id}` });
  const args = spec.oneShot(prompt, opts.model);
  const timeoutMs = opts.timeoutMs ?? envTimeoutMs('VULNORA_LOCAL_AGENT_TIMEOUT_MS', 600000);
  const maxChars = opts.maxChars ?? 4000;
  // child env: provider keys stripped + HOME pinned to the real agent home (see childEnv).
  const env = childEnv();
  const resolvedBin = resolveBin(spec.bin) || spec.bin;
  return new Promise((resolve) => {
    // stdin:'ignore' so the agent doesn't stall waiting on piped input (e.g. `claude -p`'s 3s stdin wait).
    let child: import('child_process').ChildProcess;
    try { child = spawnAgent(resolvedBin, args, { env, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch (error) { resolve({ ok: false, latencyMs: Date.now() - t0, output: '', error: String(error) }); return; }
    let out = '';
    let errOut = '';
    let done = false;
    const finish = (r: AgentRunResult): void => { if (!done) { done = true; clearTimeout(timer); resolve(r); } };
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* noop */ }
      finish({ ok: false, latencyMs: Date.now() - t0, output: out.trim().slice(0, maxChars), error: `timed out after ${timeoutMs}ms` });
    }, timeoutMs);
    child.stdout?.on('data', (d) => { if (out.length < 1_000_000) out += String(d); });
    child.stderr?.on('data', (d) => { if (errOut.length < 100_000) errOut += String(d); });
    child.on('error', (e) => finish({ ok: false, latencyMs: Date.now() - t0, output: '', error: (e as Error).message }));
    child.on('close', (code) => {
      const latencyMs = Date.now() - t0;
      const output = out.trim().slice(0, maxChars);
      const semanticError = agentFailureOutput(output);
      if (code === 0 && !semanticError) finish({ ok: true, latencyMs, output });
      else if (semanticError) finish({ ok: false, latencyMs, output, error: semanticError });
      else finish({ ok: false, latencyMs, output, error: (errOut.trim() || `exited with code ${code}`).slice(0, 300) });
    });
  });
}

/** A cheap liveness probe — asks the agent to echo a token. SPENDS a tiny bit of the agent's quota. */
export function pingLocalAgent(id: string, prompt?: string, timeoutMs?: number): Promise<AgentRunResult> {
  return runLocalAgent(id, prompt || 'Reply with exactly the single word: PONG', {
    timeoutMs: timeoutMs ?? 90000,
    maxChars: 400,
  });
}

/**
 * Drive a connected agent as the LLM BACKEND for the mission/operator flow — a long-prompt one-shot
 * that returns ONLY the model's reply text (no CLI banner). Per-agent invocation: claude/codex feed
 * the prompt via STDIN (robust for long planning prompts), codex uses --output-last-message for a
 * clean reply, hermes takes the prompt as an arg. Provider keys are stripped so each CLI uses its own
 * login (no API key needed). Throws on non-zero exit / timeout so the LLMBackbone retry/fallback fires.
 */
export interface LocalAgentProgress { agent: string; type: string; text?: string; model?: string }

export function localAgentChat(id: string, prompt: string, opts: {
  model?: string; command?: string; timeoutMs?: number; signal?: AbortSignal;
  onProgress?: (event: LocalAgentProgress) => void;
} = {}): Promise<string> {
  const spec = getSpec(id);
  if (!spec) return Promise.reject(new Error(`unknown local agent: ${id}`));
  if (opts.signal?.aborted) return Promise.reject(opts.signal.reason ?? new Error('Agent request cancelled'));
  // child env: provider keys stripped + HOME pinned to the real agent home (see childEnv).
  const env = childEnv();
  const model = opts.model && opts.model !== 'codex-default' && opts.model !== id ? opts.model
    : id === 'codex' ? process.env.VULNORA_CODEX_MODEL?.trim() || undefined : undefined;
  const timeoutMs = opts.timeoutMs ?? envTimeoutMs('VULNORA_LOCAL_AGENT_TIMEOUT_MS', 600000);

  let args: string[];
  let viaStdin = true;
  let outFile: string | null = null;
  let workDir: string | null = null;
  if (id === 'claude') {
    workDir = mkdtempSync(join(tmpdir(), 'vulnora-claudellm-'));
    args = ['--safe-mode', '-p', '--output-format', 'stream-json', '--verbose', '--include-partial-messages',
      '--tools', '', '--disallowedTools', 'mcp__*', '--no-session-persistence', '--max-turns', '1',
      ...(model ? ['--model', model] : [])];
  } else if (id === 'codex') {
    workDir = mkdtempSync(join(tmpdir(), 'vulnora-codexllm-'));
    outFile = join(workDir, 'reply.txt');
    args = ['--ask-for-approval', 'never',
      ...['shell_tool', 'unified_exec', 'apps', 'plugins', 'hooks', 'browser_use', 'computer_use', 'in_app_browser'].flatMap(feature => ['--disable', feature]),
      'exec', '-c', 'model_reasoning_effort="low"', '-c', 'web_search="disabled"', '-c', 'mcp_servers={}',
      '--ephemeral', '--skip-git-repo-check', '--json', '--color', 'never', '--sandbox', 'read-only',
      '-C', workDir, '--output-last-message', outFile, ...(model ? ['-m', model] : []), '-'];
  } else { // hermes — takes the prompt as an arg
    args = ['-z', prompt, ...(hermesYoloEnabled() ? ['--yolo'] : []), ...(model ? ['-m', model] : [])];
    viaStdin = false;
  }

  const cleanup = () => { if (workDir) { try { rmSync(workDir, { recursive: true, force: true }); } catch { /* noop */ } } };
  const command = opts.command || spec.bin;
  const resolvedBin = resolveBin(command) || command;
  return new Promise((resolve, reject) => {
    let child: import('child_process').ChildProcess;
    try { child = spawnAgent(resolvedBin, args, { env: { ...env, NO_COLOR: '1' }, windowsHide: true,
      ...(workDir ? { cwd: workDir } : {}),
      stdio: [viaStdin ? 'pipe' : 'ignore', 'pipe', 'pipe'] }); }
    catch (error) { cleanup(); reject(error); return; }
    let out = '';
    let errOut = '';
    let pending = '';
    let reply = '';
    let streamError = '';
    let protocol = false;
    let done = false;
    let failure: Error | undefined;
    let killTimer: ReturnType<typeof setTimeout> | undefined;
    const decoder = new StringDecoder('utf8');
    const stop = (error: Error) => {
      if (done || failure) return;
      failure = error;
      try { child.kill('SIGTERM'); } catch { /* close/error will settle the request */ }
      killTimer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* already closed */ } }, 2000);
    };
    const abort = () => stop(opts.signal?.reason instanceof Error ? opts.signal.reason : new Error('Agent request cancelled'));
    const finish = (fn: () => void) => {
      if (done) return;
      done = true; clearTimeout(timer); clearTimeout(killTimer);
      opts.signal?.removeEventListener('abort', abort); cleanup(); fn();
    };
    const timer = setTimeout(() => stop(new Error(`${id} timed out after ${timeoutMs}ms`)), timeoutMs);
    const line = (text: string) => {
      if (!text.trim()) return;
      let event;
      try { event = JSON.parse(text); } catch { return; } // Older CLI/test fixtures can emit plain text.
      if (!event || typeof event !== 'object' || typeof event.type !== 'string') return;
      protocol = true;
      if (id === 'codex' && event.type === 'item.completed' && event.item?.type === 'agent_message' && typeof event.item.text === 'string') reply = event.item.text;
      if (id === 'claude' && event.type === 'result' && typeof event.result === 'string') reply = event.result;
      if (id === 'claude' && event.type === 'assistant' && Array.isArray(event.message?.content)) {
        reply = event.message.content.filter((block: { type?: string; text?: unknown }) => block.type === 'text' && typeof block.text === 'string').map((block: { text: string }) => block.text).join('');
      }
      if (event.type === 'error' || event.type === 'turn.failed' || event.is_error === true) {
        streamError = String(event.error?.message || event.message || event.result || event.subtype || 'CLI stream failed');
      }
      const delta = event.event?.delta;
      const content = delta?.type === 'text_delta' && typeof delta.text === 'string' ? delta.text
        : event.type === 'item.completed' && event.item?.type === 'agent_message' ? reply : undefined;
      const reportedModel = typeof event.model === 'string' ? event.model : model;
      opts.onProgress?.({ agent: id, type: event.type, ...(content ? { text: content } : {}), ...(reportedModel ? { model: reportedModel } : {}) });
    };
    child.stdout?.on('data', (data: Buffer) => {
      if (failure) return;
      const text = decoder.write(data);
      if (out.length + text.length > 8_000_000) { stop(new Error(`${id} output exceeds the 8000000 character limit`)); return; }
      out += text;
      pending += text;
      const lines = pending.split('\n'); pending = lines.pop() || '';
      try { for (const text of lines) line(text); } catch (error) { stop(error as Error); }
    });
    child.stderr?.on('data', (data) => { errOut = (errOut + String(data)).slice(-200_000); });
    child.on('error', (error) => { failure ??= error; });
    child.on('close', (code) => {
      try { line(pending + decoder.end()); } catch (error) { failure ??= error as Error; }
      let content = reply || (protocol ? '' : out.trim());
      if (outFile && existsSync(outFile)) {
        try {
          if (statSync(outFile).size > 8_000_000) throw new Error(`${id} reply exceeds the 8000000 byte limit`);
          content = readFileSync(outFile, 'utf8').trim() || content;
        } catch (error) { failure ??= error as Error; }
      }
      finish(() => {
        const semanticError = agentFailureOutput(content);
        if (failure) reject(failure);
        else if (streamError) reject(new Error(streamError.slice(0, 800)));
        else if (code === 0 && content && !semanticError) resolve(content);
        else if (semanticError) reject(new Error(semanticError));
        else reject(new Error((errOut.trim() || content || `exited with code ${code}`).slice(0, 800)));
      });
    });
    if (viaStdin && child.stdin) {
      child.stdin.on('error', error => stop(error));
      child.stdin.end(prompt);
    }
    opts.signal?.addEventListener('abort', abort, { once: true });
    if (opts.signal?.aborted) abort();
  });
}

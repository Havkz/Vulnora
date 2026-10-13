import { afterEach, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { localAgentChat, type LocalAgentProgress } from '../agent/local-agents.js';

const directories: string[] = [];
afterEach(() => { vi.unstubAllEnvs(); for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });

function fixture(id: 'codex' | 'claude', mode = 'reply') {
  const home = realpathSync.native(mkdtempSync(join(tmpdir(), 'vulnora-transport-')));
  directories.push(home);
  const bin = join(home, 'bin'); const script = join(bin, 'node_modules', 'fixture', 'cli.mjs');
  mkdirSync(join(bin, 'node_modules', 'fixture'), { recursive: true });
  const pidFile = join(home, 'child.pid'); const invocation = join(home, 'invocation.json');
  writeFileSync(script, `import { writeFileSync } from 'node:fs';
const args = process.argv.slice(2);
writeFileSync(process.env.VULNORA_TRANSPORT_PID, String(process.pid));
writeFileSync(process.env.VULNORA_TRANSPORT_CALL, JSON.stringify({ args, cwd: process.cwd(), home: process.env.HOME, key: process.env.OPENAI_API_KEY, anthropic: process.env.ANTHROPIC_API_KEY }));
const mode = process.env.VULNORA_TRANSPORT_MODE;
let prompt = '';
process.stdin.on('data', chunk => { prompt += chunk; });
process.stdin.on('end', () => {
  if (mode === 'stall') { setInterval(() => {}, 1000); return; }
  if (mode === 'overflow') { process.stdout.write('x'.repeat(8000001)); setInterval(() => {}, 1000); return; }
  if (mode === 'file-overflow') { writeFileSync(args[args.indexOf('--output-last-message') + 1], 'x'.repeat(8000001)); return; }
  if (mode === 'error') { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'rate limit exceeded' } })); return; }
  if (mode === 'no-reply') { console.log(JSON.stringify({ type: 'thread.started', thread_id: 'fixture' })); return; }
  if (mode === 'claude-error') { console.log(JSON.stringify({ type: 'result', is_error: true, result: 'authentication expired' })); return; }
  const reply = 'Connected: 日本語 — ' + prompt;
  if (args.includes('--output-last-message')) {
    writeFileSync(args[args.indexOf('--output-last-message') + 1], reply);
    const event = Buffer.from(JSON.stringify({ type: 'item.completed', item: { type: 'agent_message', text: reply } }) + '\\n');
    const split = event.indexOf(Buffer.from('日')) + 1;
    process.stdout.write(event.subarray(0, split));
    setTimeout(() => { process.stdout.write(event.subarray(split)); setTimeout(() => {}, 120); }, 20);
  } else {
    console.log(JSON.stringify({ type: 'stream_event', event: { delta: { type: 'text_delta', text: 'Connected: ' } } }));
    console.log(JSON.stringify({ type: 'result', result: reply, is_error: false }));
  }
});`, 'utf8');
  const command = join(bin, id + (process.platform === 'win32' ? '.cmd' : ''));
  writeFileSync(command, process.platform === 'win32'
    ? '@echo off\r\nset "dp0=%~dp0"\r\nset "_prog=node"\r\n"%_prog%" "%dp0%\\node_modules\\fixture\\cli.mjs" %*\r\n'
    : `#!/bin/sh\nexec "${process.execPath}" "${script}" "$@"\n`, { mode: 0o755 });
  vi.stubEnv('VULNORA_AGENT_HOME', home);
  vi.stubEnv('VULNORA_TRANSPORT_PID', pidFile); vi.stubEnv('VULNORA_TRANSPORT_CALL', invocation);
  vi.stubEnv('VULNORA_TRANSPORT_MODE', mode);
  vi.stubEnv('OPENAI_API_KEY', 'app-key-must-not-replace-cli-login');
  vi.stubEnv('ANTHROPIC_API_KEY', 'app-key-must-not-replace-cli-login');
  return { home, command, pidFile, invocation };
}

describe('authenticated local CLI transport', () => {
  it('streams Codex JSON events before completion, preserves split UTF-8 and uses native login in an isolated directory', async () => {
    const f = fixture('codex'); const events: LocalAgentProgress[] = []; let settled = false;
    const pending = localAgentChat('codex', 'literal & < >\nsecond line', {
      command: f.command, timeoutMs: 4000, model: 'fixture-model', onProgress: event => events.push(event),
    }).finally(() => { settled = true; });
    await vi.waitFor(() => expect(events.length).toBe(1));
    expect(settled).toBe(false);
    await expect(pending).resolves.toBe('Connected: 日本語 — literal & < >\nsecond line');
    expect(events[0].text).toContain('日本語');
    const call = JSON.parse(readFileSync(f.invocation, 'utf8'));
    expect(call).toMatchObject({ home: f.home });
    expect(call.key).toBeUndefined(); expect(call.anthropic).toBeUndefined();
    expect(call.args).toContain('--json'); expect(call.args).toContain('never');
    for (const feature of ['shell_tool', 'unified_exec', 'apps', 'plugins', 'hooks', 'browser_use', 'computer_use', 'in_app_browser']) {
      expect(call.args.slice(call.args.indexOf(feature) - 1, call.args.indexOf(feature) + 1)).toEqual(['--disable', feature]);
    }
    expect(call.args).toContain('web_search="disabled"'); expect(call.args).toContain('mcp_servers={}');
    expect(call.args).toContain('fixture-model'); expect(call.cwd).not.toBe(process.cwd());
    expect(existsSync(call.cwd)).toBe(false);
  });

  it('decodes Claude streaming results and disables independent tools and CLI history', async () => {
    const f = fixture('claude'); const events: LocalAgentProgress[] = [];
    await expect(localAgentChat('claude', 'hello', { command: f.command, timeoutMs: 4000, onProgress: event => events.push(event) }))
      .resolves.toBe('Connected: 日本語 — hello');
    expect(events[0]).toMatchObject({ agent: 'claude', text: 'Connected: ' });
    const { args } = JSON.parse(readFileSync(f.invocation, 'utf8'));
    expect(args).toContain('--safe-mode'); expect(args).not.toContain('--bare');
    expect(args.slice(args.indexOf('--tools'), args.indexOf('--tools') + 2)).toEqual(['--tools', '']);
    expect(args).toContain('mcp__*'); expect(args).toContain('--no-session-persistence');
  });

  it.each([['codex', 'error', 'rate limit'], ['claude', 'claude-error', 'authentication expired']] as const)('rejects %s semantic stream failures even when the process exits zero', async (id, mode, message) => {
      const f = fixture(id, mode);
      await expect(localAgentChat(id, 'hello', { command: f.command, timeoutMs: 4000 })).rejects.toThrow(message);
    });

  it('awaits child termination and temporary-directory cleanup before resolving cancellation', async () => {
    const f = fixture('codex', 'stall'); const controller = new AbortController();
    const pending = localAgentChat('codex', 'hello', { command: f.command, timeoutMs: 4000, signal: controller.signal });
    const rejected = expect(pending).rejects.toThrow('operator stopped');
    try {
      await vi.waitFor(() => {
        expect(existsSync(f.pidFile)).toBe(true);
        expect(JSON.parse(readFileSync(f.invocation, 'utf8')).cwd).toBeTypeOf('string');
      });
      const pid = Number(readFileSync(f.pidFile, 'utf8'));
      const { cwd } = JSON.parse(readFileSync(f.invocation, 'utf8'));
      controller.abort(new Error('operator stopped')); await rejected;
      expect(() => process.kill(pid, 0)).toThrow(); expect(existsSync(cwd)).toBe(false);
    } finally { controller.abort(); await rejected; }
  });

  it('enforces the configured deadline and leaves no running child', async () => {
    const f = fixture('codex', 'stall');
    await expect(localAgentChat('codex', 'hello', { command: f.command, timeoutMs: 1000 })).rejects.toThrow('timed out after 1000ms');
    const pid = Number(readFileSync(f.pidFile, 'utf8'));
    expect(() => process.kill(pid, 0)).toThrow();
  });

  it.each(['overflow', 'file-overflow'])('rejects %s instead of silently truncating an oversized reply', async mode => {
    const f = fixture('codex', mode);
    await expect(localAgentChat('codex', 'hello', { command: f.command, timeoutMs: 4000 })).rejects.toThrow('exceeds');
  });

  it('does not launch a child when already cancelled', async () => {
    const f = fixture('codex'); const controller = new AbortController(); controller.abort(new Error('already stopped'));
    await expect(localAgentChat('codex', 'hello', { command: f.command, signal: controller.signal })).rejects.toThrow('already stopped');
    expect(existsSync(f.pidFile)).toBe(false);
  });

  it('does not treat protocol metadata without a model reply as successful inference', async () => {
    const f = fixture('codex', 'no-reply');
    await expect(localAgentChat('codex', 'hello', { command: f.command, timeoutMs: 4000 })).rejects.toThrow();
  });
});

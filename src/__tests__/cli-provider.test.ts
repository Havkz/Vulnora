import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { ProjectStore } from '../projects/store.js';

const execute = promisify(execFile);
const directories: string[] = [];
const servers: Server[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-provider-cli-')); directories.push(directory);
  const requests: { path: string; body: Record<string, unknown> }[] = [];
  let reply = 'VULNORA_READY';
  const server = createServer(async (req, res) => {
    let raw = ''; for await (const chunk of req) raw += String(chunk);
    requests.push({ path: req.url || '', body: raw ? JSON.parse(raw) : {} });
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/api/tags') res.end(JSON.stringify({ models: [{ name: 'installed:7b' }, { name: 'installed:7b' }] }));
    else if (req.url === '/api/chat') res.end(JSON.stringify({ message: { role: 'assistant', content: reply }, done: true }));
    else if (req.url === '/api/generate') res.end('{}');
    else if (req.url === '/api/ps') res.end('{"models":[]}');
    else { res.statusCode = 404; res.end('{}'); }
  });
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('No address');
  const path = join(directory, 'config.json');
  await writeFile(path, JSON.stringify({ defaultProvider: 'codex', codex: { defaultModel: 'codex-default', command: 'nonexistent-codex-for-cli-fixture' },
    local: { baseUrl: `http://127.0.0.1:${address.port}/api`, defaultModel: 'installed:7b' },
    fallback: { enabled: true, provider: 'local', model: 'fallback:7b', onApiError: true, onRateLimit: true, onRefusal: true } }));
  const env = { ...process.env, VULNORA_CONFIG_DIR: directory, VULNORA_DEFAULT_PROVIDER: 'codex',
    VULNORA_MODEL_FALLBACK: 'local', VULNORA_LOCAL_BASE_URL: `http://127.0.0.1:${address.port}/api`,
    VULNORA_LOCAL_MODEL: 'installed:7b', NO_COLOR: '1' };
  const cli = (...args: string[]) => execute(process.execPath, ['--import', 'tsx', fileURLToPath(new URL('../cli.ts', import.meta.url)), ...args],
    { env, windowsHide: true, timeout: 20000 });
  return { path, directory, env, cli, requests, setReply: (value: string) => { reply = value; } };
}

describe('CLI provider selection over actual loopback HTTP', () => {
  it('tests only the selected local model, retains it during inference and releases it afterwards', async () => {
    const { path, cli, requests } = await fixture();
    const result = await cli('test', '--provider', 'local', '--model', 'selected:7b');
    expect(result.stderr).toContain('Connection successful');
    expect(requests.map(request => request.path)).toEqual(['/api/chat', '/api/generate', '/api/ps']);
    expect(requests[0].body).toMatchObject({ model: 'selected:7b', keep_alive: -1 });
    expect(requests[1].body).toMatchObject({ model: 'selected:7b', keep_alive: 0 });
    const saved = JSON.parse(await readFile(path, 'utf8'));
    expect(saved.defaultProvider).toBe('codex'); expect(saved.local.defaultModel).toBe('installed:7b');
  }, 25000);

  it('discovers real installed models without inference or loading model weights', async () => {
    const { cli, requests } = await fixture();
    const { stdout } = await cli('models', '--provider', 'local');
    expect(stdout.match(/installed:7b/g)).toHaveLength(1);
    expect(requests.map(request => request.path)).toEqual(['/api/tags']);
  }, 25000);

  it('fails the selected test without trying its configured fallback model', async () => {
    const { cli, requests, setReply } = await fixture(); setReply('I cannot perform this task because the service is unavailable.');
    await expect(cli('test', '--provider', 'local', '--model', 'selected:7b')).rejects.toMatchObject({ code: 1 });
    expect(requests.filter(request => request.path === '/api/chat')).toHaveLength(1);
    expect(requests.some(request => request.body.model === 'fallback:7b')).toBe(false);
    expect(requests.find(request => request.path === '/api/generate')?.body).toMatchObject({ model: 'selected:7b', keep_alive: 0 });
  }, 25000);

  it('rejects ambiguous resume inputs before contacting any model', async () => {
    const { cli, requests } = await fixture();
    await expect(cli('run', 'http://127.0.0.1/', '--resume', 'saved-id')).rejects.toMatchObject({ code: 1 });
    expect(requests).toEqual([]);
    const { stdout } = await cli('run', '--help');
    expect(stdout).toContain('--resume'); expect(stdout).toContain('--fallback-on-refusal');
    expect(stdout).toContain('--config'); expect(stdout).toContain('--report-format');
  }, 25000);

  it('exports saved snapshots to another directory without using any model', async () => {
    const { directory, cli, requests } = await fixture();
    const store = new ProjectStore(join(directory, 'projects'));
    const project = await store.create('Saved report', 'http://127.0.0.1:1/');
    project.status = 'completed';
    project.report = { markdown: '# Saved result', generatedAt: 123,
      json: JSON.stringify({ schemaVersion: 1, missionId: 'saved', generatedAt: 123, findings: [] }) };
    await store.save(project);
    const output = join(directory, 'exports');
    const { stdout } = await cli('report', project.id, '--format', 'both', '--output', output);
    expect(stdout).toContain('.report.json');
    expect(await readFile(join(output, `${project.id}.report.md`), 'utf8')).toBe('# Saved result');
    expect(await readFile(join(output, `${project.id}.report.json`), 'utf8')).toBe(project.report.json);
    expect(requests).toEqual([]);
    expect((await store.load(project.id)).report).toEqual(project.report);
  }, 25000);

  it.skipIf(process.platform === 'win32')('saves a headless project on SIGINT instead of exiting before cleanup', async () => {
    const { directory, env } = await fixture();
    const profile = join(directory, 'run-profile.json');
    await writeFile(profile, JSON.stringify({ version: 1, target: 'http://127.0.0.1:1/', provider: 'local', model: 'installed:7b',
      fallbackEnabled: false, scope: ['localhost'], exclude: ['blocked.localhost'], excludeTool: ['nmap_scan'], excludeRisk: ['credential'], rateLimit: 1 }));
    const child = spawn(process.execPath, ['--import', 'tsx', fileURLToPath(new URL('../cli.ts', import.meta.url)),
      'run', '--config', profile, '--rate-limit', '2', '--exclude-risk', 'dangerous'],
    { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = ''; let id: string | undefined; let interruption: ReturnType<typeof setTimeout> | undefined;
    const timeout = setTimeout(() => child.kill('SIGKILL'), 20000);
    child.stderr.resume();
    child.stdout.on('data', chunk => {
      output += String(chunk);
      const match = output.match(/Resume: vulnora run --resume ([a-f\d-]{36})/);
      if (match && !id) { id = match[1]; interruption = setTimeout(() => child.kill('SIGINT'), 250); }
    });
    try {
      const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
      expect(code, output).toBe(130); expect(id).toBeDefined();
      const saved = JSON.parse(await readFile(join(directory, 'projects', `${id}.json`), 'utf8'));
      expect(saved.status).toBe('paused'); expect(saved.checkpoint.targets[0].address).toBe('http://127.0.0.1:1/');
      expect(saved.assessment).toEqual({ scopeHosts: ['localhost'], excludedHosts: ['blocked.localhost'], excludedTools: ['nmap_scan'], excludedRisks: ['dangerous'], requestsPerSecond: 2 });
      expect(saved.checkpoint.assessment).toEqual(saved.assessment);
      expect(output).toContain('checkpoint retained');
    } finally { clearTimeout(timeout); clearTimeout(interruption); if (child.exitCode === null) child.kill('SIGKILL'); }
  }, 25000);
});

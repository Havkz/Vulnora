import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer, type Server } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile, mkdir, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, basename } from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { Arsenal, BUILTIN_TOOLS, createToolContext } from '../arsenal/index.js';
import { ToolOrchestrator } from '../orchestrator/tool-orchestrator.js';
import { JsonlEvidenceStore } from '../orchestrator/evidence-store.js';
import { OperatorAgent } from '../operators/index.js';
import { LLMBackbone } from '../llm/index.js';
import { commandPath } from '../command-path.js';
import { AgentLoop } from '../agent/index.js';
import type { Task, TaskResult, LLMConfig } from '../types/index.js';
import { KillChainPhase } from '../types/index.js';

const servers: Server[] = [];
const ts: typeof import('typescript') = createRequire(import.meta.url)('typescript');
const directories: string[] = [];
const httpTool = BUILTIN_TOOLS.find(tool => tool.name === 'http_request')!;

async function scratch(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-regression-'));
  directories.push(directory);
  return directory;
}

async function listen(server: Server, host = '127.0.0.1'): Promise<string> {
  servers.push(server);
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, host, resolve); });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing server address');
  return `http://${host}:${address.port}`;
}

afterEach(async () => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe('audit security regressions', () => {
  it.each(['dir_bruteforce', 'api_endpoint_discovery', 'robots_txt_fetch'])(
    'builds actual paths rather than query suffixes in %s', async name => {
      const paths: string[] = [];
      const origin = await listen(createServer((request, response) => {
        paths.push(request.url || '');
        if (request.url === '/robots.txt') { response.end('User-agent: *\nDisallow: /private\n'); }
        else if (request.url === '/app/api') { response.writeHead(200, { 'content-type': 'application/json' }); response.end('{"fixture":true}'); }
        else { response.writeHead(404); response.end('missing'); }
      }));
      const tool = BUILTIN_TOOLS.find(tool => tool.name === name);
      if (!tool) throw new Error('Missing discovery tool');
      const result = await tool.handler(createToolContext(undefined, { url: origin + '/app/?mode=read' }));
      expect(result.success).toBe(true);
      expect(paths.every(path => !path.includes('mode=read'))).toBe(true);
      if (name === 'robots_txt_fetch') expect(paths).toEqual(['/robots.txt']);
      else {
        expect(paths).toContain('/app/api');
        expect(paths.some(path => path.startsWith('/app/vulnora-not-found-'))).toBe(true);
        expect(result.output).toMatch(/Found [1-9]/);
      }
    });
  it.each(['dir_bruteforce', 'api_endpoint_discovery'])('rejects uniform SPA and authentication responses in %s discovery', async name => {
    for (const status of [200, 401]) {
      const origin = await listen(createServer((_req, res) => {
        res.writeHead(status, { 'content-type': 'text/html' });
        res.end('<html>Same page for every path</html>');
      }));
      const tool = BUILTIN_TOOLS.find(tool => tool.name === name)!;
      const result = await tool.handler(createToolContext(undefined, { url: origin, wordlist: 'common' }));
      expect(result.success).toBe(true);
      expect(result.findings).toBeUndefined();
      expect(result.output).toMatch(/No (?:interesting paths|API endpoints) found/);
    }
  });

  it('requires documentation content rather than a promising path name', async () => {
    const origin = await listen(createServer((req, res) => {
      if (req.url === '/swagger') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('Ordinary page'); }
      else if (req.url === '/openapi.json') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"openapi":"3.0.0","paths":{}}'); }
      else { res.writeHead(404); res.end('missing'); }
    }));
    const tool = BUILTIN_TOOLS.find(tool => tool.name === 'api_endpoint_discovery')!;
    const result = await tool.handler(createToolContext(undefined, { url: origin }));
    const documentation = result.findings?.find(finding => finding.title === 'API Documentation Exposed');
    expect(documentation?.details).toContain('/openapi.json');
    expect(documentation?.details).not.toContain('/swagger');
  });

  it.each([true, false])('executes recovery outside role defaults once, with actual success=%s and no model call', async success => {
    const arsenal = new Arsenal();
    const handler = vi.fn(async () => ({ success, output: success ? 'TLS observation' : undefined, error: success ? undefined : 'TLS unavailable' }));
    arsenal.register({ name: 'ssl_scan', description: 'TLS', category: 'recon', handler });
    const llm = new LLMBackbone({ provider: 'local', model: 'test' });
    const chat = vi.spyOn(llm, 'chatWithTools');
    const loop = new AgentLoop(llm, arsenal, { tools: ['dns_lookup'] });
    const task: Task = { id: 'recovery', missionId: 'test', name: 'Coverage Recovery', description: 'TLS', operatorType: 'recon', phase: KillChainPhase.RECON, status: 'in_progress', priority: 1, dependencies: [], createdAt: 1, executionPlan: { toolName: 'ssl_scan', parameters: { host: '127.0.0.1' } } };
    const result = await loop.run(task, '', { id: 'local', address: '127.0.0.1' } as never);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(chat).not.toHaveBeenCalled();
    expect(result.success).toBe(success);
    expect(result.steps).toHaveLength(1);
  });

  it('does not advertise absent executables while preserving built-in tools', async () => {
    vi.stubEnv('PATH', await scratch());
    const arsenal = new Arsenal();
    arsenal.register({ name: 'nmap_scan', description: 'Nmap', category: 'recon', handler: async () => ({ success: true }) });
    arsenal.register(httpTool);
    expect((await arsenal.getReadyToolDefinitions()).map(tool => tool.name)).toEqual(['http_request']);
  });

  it('reports stored HTTP evidence and gaps for the matching host without requesting tools', async () => {
    const arsenal = new Arsenal();
    await arsenal.getOrchestrator().execute(httpTool, { parameters: { url: 'https://target.test/api/config' } }, async () => ({ success: true, output: 'Observed fixture response' }));
    arsenal.getOrchestrator().markIncompleteArea('target.test: service_detection');
    const llm = new LLMBackbone({ provider: 'local', model: 'test' });
    const chat = vi.spyOn(llm, 'chatWithTools').mockResolvedValue({ content: 'RESULT\nStatus: inconclusive', model: 'test' });
    const report = { id: 'report', name: 'Report', description: 'Summarize supplied evidence', operatorType: 'analyst' } as Task;
    await new AgentLoop(llm, arsenal).run(report, '', { id: 'fixture', address: 'target.test' } as never);
    const [messages, tools] = chat.mock.calls[0];
    expect(tools).toEqual([]);
    expect(messages.map(message => message.content).join('\n')).toContain('Observed fixture response');
    expect(messages.map(message => message.content).join('\n')).toContain('service_detection');
  });
  it.each([false, true])('blocks a real out-of-scope redirect with configured authentication = %s', async authentication => {
    let outsideRequests = 0;
    const destination = await listen(createServer((_req, res) => { outsideRequests++; res.end('outside'); }), '127.0.0.2');
    const origin = await listen(createServer((_req, res) => { res.writeHead(302, { location: destination }); res.end(); }));
    vi.stubEnv('VULNORA_TARGET_ORIGIN', origin);
    vi.stubEnv('VULNORA_TARGET_HEADERS', authentication ? JSON.stringify({ Authorization: 'Bearer synthetic-secret' }) : '');
    const arsenal = new Arsenal();
    arsenal.register(httpTool);
    arsenal.setScope({ allowedHosts: ['127.0.0.1'], allowPrivate: false, allowLoopback: false });
    const result = await arsenal.execute('http_request', createToolContext(undefined, { url: origin }));
    expect(result.success).toBe(false);
    expect(result.error).toContain('SCOPE DENIED');
    expect(outsideRequests).toBe(0);
  });

  it('preserves manual redirects for built-in cookie probes with authentication configured', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 302, headers: { location: '/login', 'set-cookie': 'session=test; Secure; HttpOnly' } }));
    vi.stubGlobal('fetch', fetch);
    vi.stubEnv('VULNORA_TARGET_ORIGIN', 'https://target.test');
    vi.stubEnv('VULNORA_TARGET_HEADERS', JSON.stringify({ Authorization: 'Bearer synthetic-secret' }));
    const cookieTool = BUILTIN_TOOLS.find(tool => tool.name === 'cookie_analysis')!;
    await cookieTool.handler(createToolContext(undefined, { url: 'https://target.test' }));
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('redacts JSONL requests and responses before persistence while retaining raw hashes and WAF policy', async () => {
    const path = join(await scratch(), 'evidence.jsonl');
    const store = new JsonlEvidenceStore(path);
    const orchestrator = new ToolOrchestrator({ evidenceStore: store });
    const secret = 'synthetic-reflected-header';
    vi.stubEnv('VULNORA_TARGET_ORIGIN', 'https://target.test');
    vi.stubEnv('VULNORA_TARGET_HEADERS', JSON.stringify({ 'X-Private': secret }));
    const body = `checking your browser ${secret}`;
    const result = await orchestrator.execute(httpTool, { parameters: { url: 'https://target.test', headers: { Authorization: 'Bearer explicit-synthetic-secret', 'X-Private': secret } } }, async () => ({
      success: true, output: body,
      metadata: { responseStatus: 403, responseBody: body, responseHeaders: { 'set-cookie': '__cf_bm=synthetic-cookie', 'x-reflection': secret } },
    }));
    await vi.waitFor(async () => {
      const content = await readFile(path, 'utf8');
      expect(content).not.toContain(secret);
      expect(content).not.toContain('explicit-synthetic-secret');
      expect(content).not.toContain('synthetic-cookie');
      const record = JSON.parse(content.trim());
      expect(record.responseBodyHash).toBe(createHash('sha256').update(body).digest('hex'));
      expect(record.normalizedSignature).toMatch(/^[a-f0-9]{64}$/);
      expect(record.responseFingerprint).toMatch(/^[a-f0-9]{64}$/);
    });
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(orchestrator.getNetworkContext('target.test').blockState).toBe('probable_edge_block');
    expect(orchestrator.getMetrics().wafEvents).toBe(1);
  });
});

describe('task cancellation', () => {
  it.each(['resolve', 'reject'])('ignores an old task that settles late via %s', async settlement => {
    const operator = new OperatorAgent('Regression', 'recon', { cooldownMs: 0, maxRetries: 0 });
    const pending = new Map<string, { resolve: (value: TaskResult) => void; reject: (reason: Error) => void; signal?: AbortSignal }>();
    operator.executeTask = (task, _target, signal) => new Promise((resolve, reject) => pending.set(task.id, { resolve, reject, signal }));
    const task = (id: string) => ({ id, name: id } as Task);
    const completed = vi.fn();
    operator.on('task:completed', completed);
    const first = operator.assignTask(task('first'));
    operator.abortActiveTask('timeout');
    expect(pending.get('first')?.signal?.aborted).toBe(true);
    const second = operator.assignTask(task('second'));
    if (settlement === 'resolve') pending.get('first')!.resolve({ success: true });
    else pending.get('first')!.reject(new Error('late failure'));
    expect((await first).success).toBe(false);
    expect(operator.state.currentTask).toBe('second');
    expect(operator.status).toBe('executing');
    expect(completed).not.toHaveBeenCalled();
    expect(operator.state.failedTasks).toBe(1);
    pending.get('second')!.resolve({ success: true });
    await second;
    expect(completed).toHaveBeenCalledTimes(1);
  });

  it('settles a cancelled cooldown without resetting a replacement task', async () => {
    const operator = new OperatorAgent('Cooldown', 'recon', { cooldownMs: 60_000, maxRetries: 0 });
    const failed = vi.fn();
    operator.on('task:failed', failed);
    operator.executeTask = async () => ({ success: true });
    const first = operator.assignTask({ id: 'first' } as Task);
    await vi.waitFor(() => expect(operator.status).toBe('cooldown'));
    operator.abortActiveTask('cancel cooldown');
    expect(failed).not.toHaveBeenCalled();
    let resolveSecond!: (result: TaskResult) => void;
    operator.executeTask = () => new Promise(resolve => { resolveSecond = resolve; });
    const second = operator.assignTask({ id: 'second' } as Task);
    await first;
    expect(operator.state.currentTask).toBe('second');
    expect(operator.status).toBe('executing');
    operator.abortActiveTask('cleanup');
    resolveSecond({ success: true });
    await second;
  });

  it('aborts the provider request without retries or cloud fallback', async () => {
    const controller = new AbortController();
    const fetch = vi.fn((_url, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init.signal!.addEventListener('abort', () => reject(init.signal!.reason), { once: true });
    }));
    vi.stubGlobal('fetch', fetch);
    const llm = new LLMBackbone({ provider: 'deepseek', model: 'test', apiKey: 'synthetic-key', baseUrl: 'https://primary.test', fallbackChain: [{ provider: 'openai', model: 'fallback', apiKey: 'synthetic-key' }] });
    const request = llm.chat([{ role: 'user', content: 'test' }], { signal: controller.signal });
    const rejected = expect(request).rejects.toThrow('stop request');
    controller.abort(new Error('stop request'));
    await rejected;
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('propagates cancellation into a real built-in HTTP request', async () => {
    let started!: () => void;
    const received = new Promise<void>(resolve => { started = resolve; });
    const origin = await listen(createServer(() => started()));
    const arsenal = new Arsenal();
    arsenal.register(httpTool);
    const controller = new AbortController();
    const request = arsenal.execute('http_request', { parameters: { url: origin }, abortSignal: controller.signal });
    await received;
    controller.abort(new Error('stop HTTP'));
    const result = await request;
    expect(result.success).toBe(false);
    expect(result.metadata?.orchestrationStatus).toBe('aborted');
  });
});

describe('provider and platform configuration', () => {
  it.each(['deepseek', 'gemini', 'xai', 'local'] as const)('retains the entire %s mission configuration in the actual server factory', async provider => {
    const source = await readFile(join(process.cwd(), 'src/server.ts'), 'utf8');
    const ast = ts.createSourceFile('server.ts', source, ts.ScriptTarget.Latest, true);
    const factory = ast.statements.find(statement => ts.isFunctionDeclaration(statement) && statement.name?.text === 'createVulnoraCommandInstance');
    expect(factory).toBeDefined();
    let captured: { llm: LLMConfig } | undefined;
    class Command {
      constructor(config: { llm: LLMConfig }) { captured = config; }
      connectBroadcast(): void { /* fixture */ }
      on(): void { /* fixture */ }
    }
    const context = vm.createContext({ vulnoraCommand: null, VulnoraCommand: Command, broadcastEvent: () => {} });
    vm.runInContext(ts.transpileModule(source.slice(factory!.getStart(ast), factory!.end), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText, context);
    const config: LLMConfig = { provider, model: 'test', apiKey: 'synthetic-key', baseUrl: 'https://custom.test/v1', timeout: 1234, maxTokens: 1024, temperature: 0.2, fallbackChain: [] };
    context.createVulnoraCommandInstance('test', config);
    expect(captured?.llm).toEqual(config);
  });

  it('finds a native executable on the current OS and rejects directories and missing commands', async () => {
    const directory = await scratch();
    const binary = process.platform === 'win32' ? 'fixture.EXE' : 'fixture';
    const executable = join(directory, binary);
    await copyFile(process.execPath, executable);
    await mkdir(join(directory, process.platform === 'win32' ? 'folder.EXE' : 'folder'));
    const env = { PATH: directory, PATHEXT: '.COM;.EXE' };
    expect(await commandPath('fixture', process.platform, env)).toBe(executable);
    expect(await commandPath('folder', process.platform, env)).toBeUndefined();
    expect(await commandPath('missing', process.platform, env)).toBeUndefined();
    expect(await commandPath(basename(process.execPath), process.platform, { PATH: dirname(process.execPath) })).toBe(process.execPath);
  });

  it('loads settings and .env from an explicit config directory', async () => {
    const directory = await scratch();
    await writeFile(join(directory, '.env'), 'VULNORA_ISOLATION_TEST=config-directory\n');
    vi.stubEnv('VULNORA_CONFIG_DIR', directory);
    vi.resetModules();
    const { config } = await import('../config/index.js');
    expect(config.getConfigPath()).toBe(join(directory, 'config.json'));
    expect(process.env.VULNORA_ISOLATION_TEST).toBe('config-directory');
    delete process.env.VULNORA_ISOLATION_TEST;
  });
});

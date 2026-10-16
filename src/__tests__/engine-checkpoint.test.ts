import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer, type Server } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { spawn, type ChildProcess } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { VulnoraCommand } from '../index.js';
import { KillChainPhase } from '../types/index.js';
import { validateEngineCheckpoint, type EngineCheckpoint } from '../projects/engine-checkpoint.js';
import { ProjectStore } from '../projects/store.js';
import { CheckpointWriteError } from '../agent/checkpoint.js';
import { runSubprocess } from '../arsenal/index.js';
import { acquireProjectLease } from '../projects/lease.js';

const commands: VulnoraCommand[] = [];
const servers: Server[] = [];
const children: ChildProcess[] = [];
const directories: string[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  for (const command of commands.splice(0)) { command.stop(); command.opsec.cleanup(); }
  for (const child of children.splice(0)) if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await new Promise<void>(resolve => child.once('exit', () => resolve())); }
  for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

function scanner(onStateCheckpoint?: () => Promise<void>): VulnoraCommand {
  const command = new VulnoraCommand({ name: 'Fixture', llm: { provider: 'mock', model: 'fixture' },
    operators: { defaultConfig: { cooldownMs: 0 } }, hooks: { onStateCheckpoint } });
  commands.push(command);
  return command;
}

function prepare(command: VulnoraCommand, origin = 'http://127.0.0.1:1234') {
  command.targetEnv.addTarget({ name: 'Fixture', type: 'web_application', zone: 'external', address: origin });
  const mission = command.mission.createMission({ name: 'Fixture', objectives: ['Read fixture'], phases: [KillChainPhase.RECON] });
  command.mission.startMission(mission.id);
  const task = command.mission.createTask({ missionId: mission.id, name: 'Read', description: `Read ${origin}`,
    phase: KillChainPhase.RECON, operatorType: 'recon' });
  task.executionPlan = { toolName: 'http_request', parameters: { url: origin } };
  return { mission, task };
}

async function tick(command: VulnoraCommand): Promise<void> {
  await (command as unknown as { tick: () => Promise<void> }).tick();
}

async function listen(server: Server): Promise<string> {
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Fixture address missing');
  return `http://127.0.0.1:${address.port}`;
}

describe('whole scanner checkpoints', () => {
  it('lets an overdue child timer run after an event-loop stall instead of aborting it as a dispatch failure', async () => {
    vi.stubEnv('VULNORA_TASK_TIMEOUT_MS', '50');
    const command = scanner();
    vi.spyOn(command.llm, 'getProvider').mockReturnValue('deterministic');
    const { task } = prepare(command);
    command.arsenal.register({ name: 'fixture_stalled_timer', description: 'Local timeout fixture', category: 'util', parameters: [],
      handler: async () => {
        const result = await runSubprocess(process.execPath, ['-e', 'setTimeout(()=>{},8000)'], { timeout: 100 });
        return { success: result.exitCode === 0, error: result.stderr };
      } });
    task.executionPlan = { toolName: 'fixture_stalled_timer', parameters: {} };
    let started = false;
    command.arsenal.on('tool:process', event => { if (event.type === 'started') started = true; });
    await tick(command);
    await vi.waitFor(() => expect(started).toBe(true), { timeout: 5000 });
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1300);
    await tick(command);
    expect(task.result?.failureKind).not.toBe('dispatch_infrastructure');
    await vi.waitFor(() => expect(task.status).toBe('failed'), { timeout: 5000 });
    expect(task.result?.failureKind).toBe('tool');
    expect(task.result?.error).toContain('Process killed (timeout)');
  }, 10000);
  it('lets a real bounded child finish after the inactivity window without stalling the mission', async () => {
    vi.stubEnv('VULNORA_TASK_TIMEOUT_MS', '50');
    const command = scanner();
    vi.spyOn(command.llm, 'getProvider').mockReturnValue('deterministic');
    const { task } = prepare(command);
    command.arsenal.register({ name: 'fixture_process', description: 'Local bounded child', category: 'util', parameters: [],
      handler: async () => {
        const result = await runSubprocess(process.execPath, ['-e', 'setTimeout(()=>process.stdout.write("Completed fixture"),200)'], { timeout: 2000 });
        return { success: result.exitCode === 0, output: result.stdout };
      } });
    task.executionPlan = { toolName: 'fixture_process', parameters: {} };
    let processStarted = false;
    command.arsenal.on('tool:process', event => { if (event.type === 'started') processStarted = true; });
    await tick(command);
    await vi.waitFor(() => expect(processStarted).toBe(true), { timeout: 5000 });
    await new Promise(resolve => setTimeout(resolve, 80));
    await tick(command);
    expect(task.status).not.toBe('failed');
    await vi.waitFor(() => expect(task.status).toBe('completed'), { timeout: 5000 });
    expect(task.result?.output).toContain('Completed fixture');
  }, 10000);
  it('retains phases, queues, IDs, results, scope, evidence, budgets, and operator settings', async () => {
    const origin = await listen(createServer((_request, response) => response.end('Fixture evidence')));
    const command = scanner();
    const { mission, task } = prepare(command, origin);
    await tick(command);
    await vi.waitFor(() => expect(task.status).toBe('completed'), { timeout: 5000 });
    const before = command.exportCheckpoint();
    validateEngineCheckpoint(before);
    const restored = scanner();
    restored.restoreCheckpoint(JSON.parse(JSON.stringify(before)));
    const after = restored.exportCheckpoint();
    expect(after.mission).toEqual(before.mission);
    expect(after.targets).toEqual(before.targets);
    expect(after.orchestrator).toEqual(before.orchestrator);
    expect(after.operators[0].id).toBe(before.operators[0].id);
    expect(after.operators[0].config.cooldownMs).toBe(0);
    expect(after.operators[0].state.completedTasks).toBe(1);
    expect(restored.arsenal.getScope()?.allowedHosts).toEqual(['127.0.0.1']);
    expect(after.mission.activeMissionId).toBe(mission.id);
    let ran = false;
    const duplicate = await restored.arsenal.execute('http_request', { parameters: { url: origin } });
    expect(duplicate.metadata?.cacheHit).toBe(true);
    const tool = restored.arsenal.getTool('http_request');
    if (!tool) throw new Error('HTTP tool missing');
    const result = await restored.arsenal.getOrchestrator().execute(tool, { parameters: { url: origin } }, async () => { ran = true; return { success: true }; });
    expect(ran).toBe(false);
    expect(result.metadata?.cacheHit).toBe(true);
  });

  it('does not start a new mission when inspecting a completed saved project', () => {
    const command = scanner();
    const { mission } = prepare(command);
    command.mission.completeMission(mission.id);
    const restored = scanner();
    restored.restoreCheckpoint(JSON.parse(JSON.stringify(command.exportCheckpoint())));
    expect(() => restored.start()).toThrow('completed');
    expect(restored.generateReport(mission.id)).toContain('# Security Assessment Report');
    expect(restored.generateReport()).toContain('# Security Assessment Report');
    expect(restored.mission.getAllMissions()).toHaveLength(1);
  });

  it.each(['version', 'target', 'task', 'budget', 'agent_context'])('rejects corrupt %s before mutating the scanner', key => {
    const command = scanner();
    prepare(command);
    const saved = command.exportCheckpoint();
    if (key === 'version') (saved as { version: number }).version = 99;
    if (key === 'target') saved.targets[0].address = 'javascript:alert(1)';
    if (key === 'task') saved.mission.tasks[0].missionId = 'missing';
    if (key === 'budget') saved.orchestrator.budgets = [['fixture', { limits: { total_request_budget: -1 }, used: {} } as never]];
    if (key === 'agent_context') saved.mission.tasks[0].checkpoint = { version: 99 } as never;
    const restored = scanner();
    expect(() => restored.restoreCheckpoint(saved)).toThrow();
    expect(restored.targetEnv.getAllTargets()).toEqual([]);
    expect(restored.mission.getAllMissions()).toEqual([]);
  });

  it('saves charged request budgets before executing and propagates write failure through Arsenal', async () => {
    const command = scanner(async () => { throw new Error('disk full'); });
    let ran = false;
    const tool = command.arsenal.getTool('http_request');
    if (!tool) throw new Error('HTTP tool missing');
    await expect(command.arsenal.getOrchestrator().execute(tool,
      { parameters: { url: 'http://127.0.0.1/' } }, async () => { ran = true; return { success: true }; })).rejects.toBeInstanceOf(CheckpointWriteError);
    expect(ran).toBe(false);
    expect(command.arsenal.getOrchestrator().getBudget('127.0.0.1').used.http_request_budget).toBe(1);
    await expect(command.arsenal.execute('http_request', { parameters: { url: 'http://127.0.0.1/other' } })).rejects.toBeInstanceOf(CheckpointWriteError);
  });

  it.each(['http_request', 'api_endpoint_discovery'])('drains an in-flight %s before returning a resumable pause', async toolName => {
    let received!: () => void;
    const started = new Promise<void>(resolve => { received = resolve; });
    const origin = await listen(createServer(() => received()));
    const command = scanner();
    const { task } = prepare(command, origin);
    task.executionPlan = { toolName, parameters: { url: origin } };
    command.start();
    await tick(command);
    await started;
    const first = command.pauseAndDrain();
    expect(command.pauseAndDrain()).toBe(first);
    await first;
    expect(task.status).toBe('pending');
    expect(command.isRunning()).toBe(false);
    expect(command.cell.getAllOperators().every(operator => operator.state.currentTask === null)).toBe(true);
    const saved = command.exportCheckpoint();
    expect(saved.mission.tasks[0].checkpoint?.activeCall?.name).toBe(toolName);
    expect(() => validateEngineCheckpoint(saved)).not.toThrow();
  });

  it.each(['queue', 'decomposed', 'discovery'])('recovers a %s task after killing a real scanner process without repeating the completed request', async mode => {
    const requests = { first: 0, second: 0 };
    let resume = false;
    const origin = await listen(createServer((request, response) => {
      if (request.url === '/first') { requests.first++; response.end('First result persisted'); }
      else if (request.url === '/second' || mode === 'discovery') {
        expect(request.method).toBe('GET');
        requests.second++;
        if (resume && mode === 'discovery') {
          response.writeHead(request.url === '/api/config' ? 200 : 404, { 'Content-Type': 'application/json' });
          response.end(request.url === '/api/config' ? '{"fixture":true}' : '{"notFound":true}');
        } else if (resume) response.end('Second result resumed');
      }
      else { response.writeHead(404); response.end(); }
    }));
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-crash-'));
    directories.push(directory);
    const worker = fileURLToPath(new URL('./fixtures/project-crash-worker.mjs', import.meta.url));
    const child = spawn(process.execPath, ['--import', 'tsx', worker, origin, directory, mode], {
      cwd: process.cwd(), env: { ...process.env, VULNORA_CONFIG_DIR: join(directory, 'config'), VULNORA_FULL_ARSENAL: 'off' }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    children.push(child);
    let output = ''; let errors = '';
    child.stdout?.on('data', data => { output += data.toString(); });
    child.stderr?.on('data', data => { errors += data.toString(); });
    await vi.waitFor(() => {
      if (child.exitCode !== null) throw new Error(`Worker exited: ${errors}`);
      expect(output).toMatch(/READY [a-f\d-]+/);
      expect(requests.second).toBe(1);
    }, { timeout: 15_000 });
    const id = output.match(/READY ([a-f\d-]+)/)?.[1];
    if (!id) throw new Error('Worker project ID missing');
    const exited = new Promise<void>(resolve => child.once('exit', () => resolve()));
    child.kill('SIGKILL'); await exited;
    const release = await acquireProjectLease(directory, id);
    await release();
    const project = await new ProjectStore(directory).load(id);
    if (mode === 'discovery') {
      expect((project.checkpoint as EngineCheckpoint).mission.tasks.find(task => task.name === 'second')?.checkpoint?.activeCall?.name).toBe('api_endpoint_discovery');
    } else if (mode === 'decomposed') {
      const tree = (project.checkpoint as EngineCheckpoint).mission.tasks[0].decomposition;
      expect(tree?.tasks[0]).toMatchObject({ status: 'completed', result: { success: true } });
      expect(tree?.tasks[1].checkpoint?.activeCall?.name).toBe('http_request');
    }
    const restored = scanner();
    restored.restoreCheckpoint(project.checkpoint);
    const reservedBefore = restored.arsenal.getOrchestrator().getBudget('127.0.0.1').used.total_request_budget;
    const receivedBefore = requests.first + requests.second;
    resume = true;
    await tick(restored);
    await vi.waitFor(() => expect(restored.mission.getTaskQueue().getForMission(restored.mission.getAllMissions()[0].id).every(task => task.status === 'completed')).toBe(true), { timeout: mode === 'discovery' ? 15_000 : 5000 });
    expect(requests).toEqual({ first: 1, second: mode === 'discovery' ? 26 : 2 });
    const used = restored.arsenal.getOrchestrator().getBudget('127.0.0.1').used;
    expect(used.http_request_budget).toBe(mode === 'discovery' ? 1 : 3);
    expect(used.total_request_budget).toBe(reservedBefore + requests.first + requests.second - receivedBefore);
    if (mode === 'discovery') {
      expect(restored.arsenal.getOrchestrator().getEvidence().some(record => record.toolName === 'api_endpoint_discovery'
        && record.result.success && record.rawOutput.includes('/api/config'))).toBe(true);
    }
    expect(restored.arsenal.getOrchestrator().getEvidence().some(record => record.parsedOutput?.responseBody === 'First result persisted')).toBe(true);
  }, 20_000);

  it('preserves complete multiline log content instead of cutting it at 2000 characters', () => {
    const command = scanner();
    const { task } = prepare(command);
    const operator = command.spawnOperator('Log fixture', 'recon');
    const detail = 'A complete technical observation with spaces.\n'.repeat(300);
    let observed = '';
    command.on('scan:progress', event => { observed = event.detail; });
    operator.emit('agent:thinking', { task, content: detail });
    expect(observed).toBe(detail);
    expect(command.exportCheckpoint().command.progressEvents[0].detail).toBe(detail);
  });

  it('uses a persisted POST completion receipt after a crash instead of replaying the write', async () => {
    let writes = 0;
    const origin = await listen(createServer((request, response) => {
      if (request.method === 'POST') writes++;
      response.writeHead(201, { 'content-type': 'application/json' }); response.end('{"fixture":"write-completed"}');
    }));
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-receipt-'));
    directories.push(directory);
    const worker = fileURLToPath(new URL('./fixtures/project-crash-worker.mjs', import.meta.url));
    const child = spawn(process.execPath, ['--import', 'tsx', worker, origin, directory, 'write'], {
      cwd: process.cwd(), env: { ...process.env, VULNORA_CONFIG_DIR: join(directory, 'config'), VULNORA_FULL_ARSENAL: 'off' }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    children.push(child);
    let output = ''; let errors = '';
    child.stdout?.on('data', data => { output += data.toString(); });
    child.stderr?.on('data', data => { errors += data.toString(); });
    await vi.waitFor(() => {
      if (child.exitCode !== null) throw new Error(`Worker exited: ${errors}`);
      expect(output).toMatch(/READY [a-f\d-]+/);
    }, { timeout: 15_000 });
    const id = output.match(/READY ([a-f\d-]+)/)?.[1];
    if (!id) throw new Error('Worker project ID missing');
    const exited = new Promise<void>(resolve => child.once('exit', () => resolve()));
    child.kill('SIGKILL'); await exited;
    const project = await new ProjectStore(directory).load(id);
    const restored = scanner();
    restored.restoreCheckpoint(project.checkpoint);
    expect(restored.mission.getTaskQueue().getForMission(restored.mission.getAllMissions()[0].id)[0].checkpoint?.activeCall?.arguments.method).toBe('POST');
    await tick(restored);
    await vi.waitFor(() => expect(restored.mission.getTaskQueue().getForMission(restored.mission.getAllMissions()[0].id)[0].status).toBe('completed'), { timeout: 5000 });
    expect(writes).toBe(1);
    expect(restored.arsenal.getExecutions()).toEqual([]);
    expect(restored.arsenal.getOrchestrator().getBudget('127.0.0.1').used.http_request_budget).toBe(1);
  }, 20_000);

  it('prevents concurrent local ownership and releases the project lease idempotently', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-lease-'));
    directories.push(directory);
    const id = 'aabbccdd-1111-2222-3333-444444444444';
    const release = await acquireProjectLease(directory, id);
    try { await expect(acquireProjectLease(directory, id)).rejects.toThrow('exclusive project access'); }
    finally { await release(); }
    await release();
    await (await acquireProjectLease(directory, id))();
  });
});

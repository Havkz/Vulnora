import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer, type Server } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AgentLoop } from '../agent/index.js';
import { Arsenal, BUILTIN_TOOLS } from '../arsenal/index.js';
import { LLMBackbone, LLMUnavailableError } from '../llm/index.js';
import { KillChainPhase, type Target, type Task } from '../types/index.js';

const cli = vi.hoisted(() => vi.fn());
vi.mock('../agent/local-agents.js', async original => ({
  ...await original<typeof import('../agent/local-agents.js')>(), localAgentChat: cli,
}));
const servers: Server[] = []; const directories: string[] = [];
afterEach(async () => {
  vi.unstubAllEnvs(); vi.restoreAllMocks();
  for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function fixture() {
  const requests: { method?: string; url?: string }[] = [];
  const server = createServer((request, response) => {
    requests.push({ method: request.method, url: request.url });
    response.setHeader('Content-Security-Policy', "default-src 'self'"); response.end('Fixture');
  }); servers.push(server);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('Missing fixture port');
  const url = `http://127.0.0.1:${address.port}/original?mode=read`;
  const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === 'header_analysis'));
  arsenal.setScope({ allowedHosts: ['127.0.0.1'], allowLoopback: false, allowPrivate: false, exactHosts: true });
  const task: Task = { id: 'deterministic-task', missionId: 'fixture', name: 'Web probing', description: 'Read headers',
    phase: KillChainPhase.RECON, operatorType: 'recon', priority: 1, status: 'in_progress', dependencies: [], createdAt: 1 };
  return { requests, arsenal, task, target: { id: 'fixture', address: url } as Target };
}

describe('real evidence-only fallback', () => {
  it('supplies and refreshes shared tool observations for a scanning agent before each plan', async () => {
    const f = await fixture();
    await f.arsenal.execute('header_analysis', { parameters: { url: f.target.address } });
    const llm = new LLMBackbone({ provider: 'mock', model: 'fixture' });
    const plans: string[] = [];
    vi.spyOn(llm, 'chatWithTools').mockImplementation(async messages => {
      plans.push(messages.map(message => message.content).join('\n'));
      return plans.length === 1 ? { content: 'Inspect a different endpoint', model: 'fixture', toolCalls: [
        { id: 'different', name: 'header_analysis', arguments: { url: f.target.address + '&endpoint=second' } },
      ], usage: { promptTokens: 40, completionTokens: 10, totalTokens: 50 } } : { content: 'RESULT\nStatus: inconclusive', model: 'fixture', usage: { promptTokens: 40, completionTokens: 10, totalTokens: 50 } };
    });
    await new AgentLoop(llm, f.arsenal, { tools: ['header_analysis'] }).run(f.task, '', f.target);
    expect(plans).toHaveLength(2);
    expect(plans[0]).toContain('SHARED SCAN STATE\n');
    expect(plans[0]).toContain(f.target.address);
    expect(plans[0]).toContain("default-src 'self'");
    expect(plans[0]).not.toContain('endpoint=second');
    expect(plans[1]).toContain('endpoint=second');
    expect(plans[1].match(/SHARED SCAN STATE/g)).toHaveLength(1);
    expect(f.requests).toHaveLength(2);
  });
  it('runs a real scoped HEAD check without AI requests, preserves evidence and makes the limitations explicit', async () => {
    const f = await fixture(); const llm = new LLMBackbone({ provider: 'deterministic', model: 'evidence-only' });
    const planning = vi.spyOn(llm, 'chatWithTools'); const summary = vi.spyOn(llm, 'chat');
    const result = await new AgentLoop(llm, f.arsenal, { tools: ['header_analysis'] }).run(f.task, '', f.target);
    expect(f.requests).toEqual([{ method: 'HEAD', url: '/original?mode=read' }]);
    expect(planning).not.toHaveBeenCalled(); expect(summary).not.toHaveBeenCalled();
    expect(result.success).toBe(true); expect(result.tokensUsed).toBe(0); expect(result.iterations).toBe(0);
    expect(result.summary).toContain('Deterministic checks cannot replace AI analysis');
    expect(result.steps[0].toolResult?.output).toContain("default-src 'self'");
    expect(f.arsenal.getOrchestrator().getEvidence()).toHaveLength(1);
    const resumed = await new AgentLoop(llm, f.arsenal, { tools: ['header_analysis'] }).run(f.task, '', f.target);
    expect(resumed.steps).toEqual(result.steps); expect(f.requests).toHaveLength(1);
  });

  it('uses saved evidence for reporting without executing fresh scan tools', async () => {
    const f = await fixture(); f.task.operatorType = 'analyst'; f.task.phase = KillChainPhase.ACTIONS;
    const llm = new LLMBackbone({ provider: 'deterministic', model: 'evidence-only' });
    const result = await new AgentLoop(llm, f.arsenal, { tools: ['header_analysis'] }).run(f.task, '', f.target);
    expect(f.requests).toEqual([]); expect(result.findings).toEqual([]); expect(result.summary).toContain('inconclusive');
  });

  it('records primary/local failure and switches truthfully to non-AI without a simulated model answer', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-fallback-')); directories.push(directory);
    vi.stubEnv('VULNORA_MODEL_FALLBACK_LOG', join(directory, 'fallback.jsonl'));
    cli.mockRejectedValue(new Error('Codex authentication expired'));
    const backbone = new LLMBackbone({ provider: 'codex', model: 'codex-default',
      fallbackChain: [{ provider: 'local', model: 'offline:7b', baseUrl: 'http://127.0.0.1:9/api' },
        { provider: 'deterministic', model: 'evidence-only' }] });
    const events: unknown[] = []; backbone.on('request:fallback', event => events.push(event));
    await expect(backbone.prompt('No target probes; check provider fallback')).rejects.toBeInstanceOf(LLMUnavailableError);
    expect(backbone.getActiveProvider()).toEqual({ provider: 'deterministic', model: 'evidence-only' });
    expect(events).toHaveLength(2); expect(cli).toHaveBeenCalledOnce();
    expect(events).toMatchObject([{ fromProvider: 'codex', toProvider: 'local' }, { fromProvider: 'local', toProvider: 'deterministic' }]);
  });
});

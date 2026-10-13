import { describe, expect, it, vi } from 'vitest';
import { AgentLoop } from '../agent/index.js';
import type { Arsenal } from '../arsenal/index.js';
import type { LLMBackbone } from '../llm/index.js';
import { KillChainPhase, type Target, type Task } from '../types/index.js';

describe('local-agent reconnaissance target handling', () => {
  it.each([
    ['Web probing', 'http://fixture.test:8080/base?mode=read', {}, 'header_analysis', { url: 'http://fixture.test:8080/base?mode=read' }],
    ['Content discovery', 'https://[::1]:8443/base', {}, 'robots_txt_fetch', { url: 'https://[::1]:8443/base' }],
    ['Web probing', '2001:db8::10', {}, 'header_analysis', { url: 'https://[2001:db8::10]' }],
    ['DNS Enumeration', 'https://fixture.test:8443/base', {}, 'dns_lookup', { domain: 'fixture.test', type: 'A' }],
    ['Port detection', 'http://[::1]:8080/base', {}, 'port_scan', { target: '::1', ports: '80,443', timeout: 2000 }],
    ['Web probing', 'fixture.test', { url: 'http://fixture.test:9000/legacy/path' }, 'header_analysis', { url: 'http://fixture.test:9000/legacy/path' }],
    ['Web probing', 'fixture.test', { url: 'http://other.test' }, 'header_analysis', { url: 'https://fixture.test' }],
  ])('preserves the intended %s target %s', async (name, address, metadata, tool, parameters) => {
    const definitions = [{ name: tool, description: tool, parameters: { type: 'object', properties: {} } }];
    const execute = vi.fn().mockResolvedValue({ success: true, output: 'Fixture evidence' });
    const arsenal = { execute, getReadyToolDefinitions: async () => definitions, getToolDefinitions: () => definitions,
      getOrchestrator: () => ({ getEvidence: () => [] }) } as unknown as Arsenal;
    const llm = { getProvider: () => 'local-agent', getPromptProfile: () => 'large_model',
      chatWithTools: vi.fn().mockResolvedValue({ content: 'RESULT\nStatus: inconclusive', model: 'fixture' }),
      chat: vi.fn().mockResolvedValue({ content: 'RESULT\nStatus: inconclusive', model: 'fixture' }) } as unknown as LLMBackbone;
    const task: Task = { id: 'task', missionId: 'mission', name, description: name, phase: KillChainPhase.RECON,
      operatorType: 'recon', status: 'in_progress', priority: 1, dependencies: [], createdAt: 1 };
    await new AgentLoop(llm, arsenal, { tools: [tool] }).run(task, '', { id: 'target', address, metadata } as Target);
    expect(execute).toHaveBeenCalledOnce();
    expect(execute.mock.calls[0][0]).toBe(tool);
    expect(execute.mock.calls[0][1].parameters).toEqual(parameters);
  });
});

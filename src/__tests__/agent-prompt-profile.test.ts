import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AGENT_PROMPT_PROFILES,
  buildMissionPrompt,
  compactKnownEvidence,
  resolveAgentPromptProfile,
  selectRelevantTools,
} from '../agent/prompt-profile.js';
import { classifySoftFailure, isContextCompactionNotice, LLMBackbone } from '../llm/index.js';
import { KillChainPhase, type LLMToolDefinition, type Target, type Task } from '../types/index.js';

const task = (description = 'Validate whether the target permits authentication bypass or data access.'): Task => ({
  id: 'task-1', missionId: 'mission-1', name: 'Auth bypass validation', description,
  phase: KillChainPhase.EXPLOIT, operatorType: 'exploiter', status: 'in_progress', priority: 1,
  dependencies: [], createdAt: 1,
});

const target = (): Target => ({
  id: 'target-1', name: 'Example', type: 'host', zone: 'external', status: 'vulnerable',
  address: 'example.test', port: 443, discoveredAt: 1, services: [], credentials: [],
  vulnerabilities: [
    { id: '1', name: 'Missing DMARC policy', description: 'No enforcement policy was observed.', severity: 'low', evidenceStatus: 'observed', evidence: 'TXT record is p=none.' },
    { id: '2', name: ' missing  dmarc policy ', description: 'Duplicate observation.', severity: 'medium', evidenceStatus: 'validated', evidence: 'Resolver confirmed p=none.' },
    { id: '3', name: 'SPF soft fail', description: 'SPF ends in soft-fail.', severity: 'low', evidenceStatus: 'observed' },
  ],
});

const definition = (name: string, description = `${name} verbose description`): LLMToolDefinition => ({
  name, description, parameters: { type: 'object', properties: { target: { type: 'string' } }, required: ['target'] },
});

const arsenal = [
  'curl_request', 'http_request', 'sqli_scan', 'xss_scan', 'ssti_test', 'lfi_test',
  'open_redirect_test', 'nuclei_scan', 'http_methods_test', 'api_endpoint_discovery',
  'jwt_decode', 'header_analysis', 'technology_detect', 'nmap_scan', 'port_scan',
  'ffuf_fuzz', 'gobuster_tool', 'password_spray', 'hash_crack',
].map(name => definition(name));

describe('agent prompt profiles', () => {
  it('uses the bounded 30B budget', () => {
    expect(AGENT_PROMPT_PROFILES.small_model_30b).toMatchObject({
      maxTools: 12, maxToolCalls: 12, maxIterations: 12, maxTotalTokens: 8_000,
      responseTokens: 1536,
    });
  });

  it('allows a bounded runtime override of the total 30B token budget', () => {
    const previous = process.env.T3MP3ST_SMALL_MODEL_TOTAL_TOKEN_BUDGET;
    try {
      process.env.T3MP3ST_SMALL_MODEL_TOTAL_TOKEN_BUDGET = '9500';
      expect(resolveAgentPromptProfile('small_model_30b').maxTotalTokens).toBe(9500);
      process.env.T3MP3ST_SMALL_MODEL_TOTAL_TOKEN_BUDGET = '500';
      expect(resolveAgentPromptProfile('small_model_30b').maxTotalTokens).toBe(8000);
    } finally {
      if (previous === undefined) delete process.env.T3MP3ST_SMALL_MODEL_TOTAL_TOKEN_BUDGET;
      else process.env.T3MP3ST_SMALL_MODEL_TOTAL_TOKEN_BUDGET = previous;
    }
  });

  it('uses the mission-wide specialization and documents cumulative token accounting', () => {
    const prompt = buildMissionPrompt({
      task: task(), target: target(), tools: [], profile: AGENT_PROMPT_PROFILES.small_model_30b,
    });
    expect(prompt).toContain('Specialization: Validate only reproducible, in-scope security findings relevant to the mission.');
    expect(prompt).toContain('8000 cumulative model tokens');
    expect(prompt).toContain('tool output counts when it is included in a later model prompt');
  });

  it('deduplicates findings and keeps the strongest evidence state', () => {
    const evidence = compactKnownEvidence(target(), AGENT_PROMPT_PROFILES.small_model_30b);
    expect(evidence.filter(line => /dmarc/i.test(line))).toHaveLength(1);
    expect(evidence.join('\n')).toContain('[validated]');
  });

  it('does not cut findings or expose truncation placeholders', () => {
    const t = target();
    t.vulnerabilities![0].evidence = `${'complete evidence words '.repeat(80)}Final sentence.`;
    const prompt = buildMissionPrompt({
      task: task(), target: t, tools: [], profile: AGENT_PROMPT_PROFILES.small_model_30b,
      security: { allowedHosts: ['example.test'], authorization: 'Authorized.', receipt: 'receipt-1' },
    });
    expect(prompt).not.toMatch(/\.\.\.|truncated/i);
    for (const line of prompt.split('\n').filter(line => line.startsWith('- ['))) expect(line).toMatch(/[.!?] \| impact=/);
  });

  it('states that mail-policy evidence does not prove RCE, data access, or auth bypass', () => {
    const prompt = buildMissionPrompt({
      task: task('Find RCE or authentication bypass.'), target: target(), tools: [],
      profile: AGENT_PROMPT_PROFILES.small_model_30b,
      security: { allowedHosts: ['example.test'], authorization: 'Authorized.', receipt: 'receipt-1' },
    });
    expect(prompt).toContain('does not support RCE, data access, or authentication bypass');
    expect(prompt).toContain('Do not claim exploitation');
  });

  it('blocks network, intrusive and credential tools when scope/receipt are missing', () => {
    const selected = selectRelevantTools(arsenal, task(), AGENT_PROMPT_PROFILES.small_model_30b, {}, false);
    expect(selected.map(tool => tool.name)).toEqual(['jwt_decode']);
  });

  it('does not offer functionally equivalent tools together', () => {
    const selected = selectRelevantTools(arsenal, task(), AGENT_PROMPT_PROFILES.large_model, {
      receipt: 'receipt-1', intrusiveAllowed: true, credentialToolsAllowed: true,
    });
    const names = selected.map(tool => tool.name);
    expect(names).not.toEqual(expect.arrayContaining(['curl_request', 'http_request']));
    expect(names).not.toEqual(expect.arrayContaining(['nmap_scan', 'port_scan']));
    expect(names.filter(name => ['ffuf_fuzz', 'gobuster_tool'].includes(name))).toHaveLength(1);
  });

  it('keeps only relevant schemas and never copies verbose descriptions into the mission prompt', () => {
    const tools = selectRelevantTools(arsenal, task(), AGENT_PROMPT_PROFILES.small_model_30b, {
      receipt: 'receipt-1', intrusiveAllowed: true, credentialToolsAllowed: true,
    });
    const prompt = buildMissionPrompt({ task: task(), target: target(), tools, profile: AGENT_PROMPT_PROFILES.small_model_30b });
    expect(tools.length).toBeLessThanOrEqual(12);
    expect(prompt).not.toContain('verbose description');
    expect(prompt).not.toContain('curl_request(');
  });

  it('makes the large profile materially broader without repeating evidence', () => {
    const richTarget = target();
    richTarget.vulnerabilities = Array.from({ length: 30 }, (_, index) => ({
      id: `finding-${index}`,
      name: `Distinct finding ${index}`,
      description: `Observed condition ${index}.`,
      severity: 'medium' as const,
      evidenceStatus: 'observed' as const,
      evidence: `Unique evidence ${index} ${'with additional relevant context '.repeat(20)}completed.`,
      impact: `Mission impact ${index}.`,
    }));
    const security = { receipt: 'receipt-1', intrusiveAllowed: true, credentialToolsAllowed: true };
    const smallTools = selectRelevantTools(arsenal, task(), AGENT_PROMPT_PROFILES.small_model_30b, security);
    const largeTools = selectRelevantTools(arsenal, task(), AGENT_PROMPT_PROFILES.large_model, security);
    const smallEvidence = compactKnownEvidence(richTarget, AGENT_PROMPT_PROFILES.small_model_30b);
    const largeEvidence = compactKnownEvidence(richTarget, AGENT_PROMPT_PROFILES.large_model);
    const smallPrompt = buildMissionPrompt({ task: task(), target: richTarget, tools: smallTools, profile: AGENT_PROMPT_PROFILES.small_model_30b });
    const largePrompt = buildMissionPrompt({ task: task(), target: richTarget, tools: largeTools, profile: AGENT_PROMPT_PROFILES.large_model });

    expect(largeTools.length).toBeGreaterThan(smallTools.length);
    expect(largeEvidence).toHaveLength(24);
    expect(smallEvidence).toHaveLength(8);
    expect(largeEvidence[0].length).toBeGreaterThan(smallEvidence[0].length);
    expect(largePrompt).toContain('Explain briefly why the selected test is highest-value');
    expect(smallPrompt).toContain('Use one short evidence-linked sentence');
    expect(new Set(largeEvidence).size).toBe(largeEvidence.length);
  });
});

describe('local context compaction', () => {
  const originalFetch = global.fetch;
  afterEach(() => { global.fetch = originalFetch; vi.restoreAllMocks(); });

  it('preserves the mission contract and removes transport compaction notices', async () => {
    let sent = '';
    global.fetch = vi.fn(async (_url, init) => {
      sent = String(init?.body || '');
      return new Response(JSON.stringify({ message: { content: 'RESULT\nStatus: inconclusive' }, done: true }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;
    const mission = 'ROLE\nPlanner.\n\nSCOPE\nTargets: example.test\n\nMISSION\nObjective: preserve-me.\n\nKNOWN EVIDENCE\n- None.\n\nWORKFLOW\n1. Verify.\n\nOUTPUT\nRESULT\nStatus: validated | inconclusive';
    const notice = 'Some previous conversation history has been removed for context limits.';
    await new LLMBackbone({ provider: 'local', model: 'qwen3:30b', baseUrl: 'http://localhost:11434/api' } as never)
      .chat([{ role: 'user', content: mission }, { role: 'assistant', content: 'x'.repeat(12_000) }, { role: 'user', content: notice }]);
    expect(sent).toContain('Objective: preserve-me.');
    expect(sent).toContain('Targets: example.test');
    expect(sent).toContain('Status: validated | inconclusive');
    expect(sent).not.toContain(notice);
  });

  it('classifies a compaction notice as an empty response so fallback/retry handles it', () => {
    const notice = 'Some previous conversation history has been removed for context limits.';
    expect(isContextCompactionNotice(notice)).toBe(true);
    expect(classifySoftFailure({ content: notice, model: 'test' })).toBe('empty');
  });

  it('selects the compact profile when a 30B fallback is configured', () => {
    const llm = new LLMBackbone({
      provider: 'codex', model: 'codex-default',
      fallbackChain: [{ provider: 'local', model: 'qwen3-coder:30b', baseUrl: 'http://localhost:11434/api' }],
    } as never);
    expect(llm.getPromptProfile()).toBe('small_model_30b');
  });
});

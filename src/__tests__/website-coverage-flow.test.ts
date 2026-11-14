import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer, type Server } from 'node:http';
import { VulnoraCommand } from '../index.js';
import { KillChainPhase } from '../types/index.js';
import { evaluateCoverage, VALIDATION_COVERAGE } from '../orchestrator/coverage.js';

const commands: VulnoraCommand[] = [];
const servers: Server[] = [];
afterEach(async () => {
  for (const command of commands.splice(0)) { await command.pauseAndDrain(); command.stop(); command.opsec.cleanup(); }
  for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});

describe('real website coverage recovery flow', () => {
  it('reviews public authentication and runs both observed-input checks before leaving Scanning', async () => {
    const paths: string[] = [];
    const server = createServer((request, response) => {
      paths.push(request.url || '/');
      if (request.url === '/api/private') { response.writeHead(401); response.end('Authentication required'); return; }
      if (request.url === '/app.js') { response.writeHead(200, { 'content-type': 'text/javascript' }); response.end("fetch('/api/unverified')"); return; }
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end(request.url === '/' ? '<a href=/docs>Documentation</a><script src=/app.js></script>'
        : request.url === '/docs' ? '<form action=/search method=get><input name=q></form>' : 'A fixed response with safely encoded inputs.');
    }); servers.push(server);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('Missing local address');
    const url = `http://127.0.0.1:${address.port}/`;
    const command = new VulnoraCommand({ name: 'Coverage flow', llm: { provider: 'deterministic', model: 'evidence-only' }, operators: { defaultConfig: { cooldownMs: 0 } } }); commands.push(command);
    const target = command.targetEnv.addTarget({ name: 'Fixture', address: url, type: 'web_application', zone: 'external' });
    const mission = command.mission.createMission({ name: 'Fixture', objectives: [], phases: [KillChainPhase.WEAPONIZE, KillChainPhase.DELIVER, KillChainPhase.ACTIONS] });
    command.mission.startMission(mission.id);
    const baseline = command.mission.createTask({ missionId: mission.id, name: 'Previous scan', description: url, phase: KillChainPhase.WEAPONIZE, operatorType: 'scanner' });
    command.mission.getTaskQueue().complete(baseline.id, { success: true });
    const report = command.mission.createTask({ missionId: mission.id, name: 'Future report', description: url, phase: KillChainPhase.ACTIONS, operatorType: 'analyst' });
    await command.arsenal.execute('http_request', { target, parameters: { url } });
    await command.arsenal.execute('http_request', { target, parameters: { url: url + 'api/private' } });
    const orchestrator = command.arsenal.getOrchestrator(); const saved = orchestrator.exportCheckpoint();
    const template = saved.records[0]; if (!template) throw new Error('Missing HTTP evidence');
    for (const name of ['nuclei_scan', 'http_methods_test']) {
      saved.records.push({ ...structuredClone(template), id: `fixture-${name}`,
        toolName: name, toolCategory: 'active_validation', normalizedSignature: `fixture-${name}`, equivalentSignature: `fixture-${name}`,
        resultType: 'negative', rawOutput: 'Previously completed fixture baseline.', result: { success: true, output: 'Previously completed fixture baseline.' } });
    }
    orchestrator.restoreCheckpoint(saved);
    orchestrator.markIncompleteArea(`${url}: input_surface`); orchestrator.markIncompleteArea(`${url}: authentication_testing`);
    const ready = vi.spyOn(command.arsenal, 'getReadyToolDefinitions');
    ready.mockImplementation(async (_categories, names) => command.arsenal.getToolDefinitions(undefined, names || ['web_surface_review', 'xss_scan', 'sqli_scan']));
    const engine = command as unknown as { tick(): Promise<void>; taskSeeded: boolean; dispatchPromises: Map<string, Promise<void>> };
    engine.taskSeeded = true;
    for (let turn = 0; turn < 15 && mission.currentPhase === KillChainPhase.WEAPONIZE; turn++) {
      await engine.tick(); await Promise.all([...engine.dispatchPromises.values()]);
    }
    expect(mission.currentPhase).toBe(KillChainPhase.DELIVER);
    expect(report.status).toBe('pending');
    expect(orchestrator.getMetrics().incompleteAreas).not.toContain(`${url}: input_surface`);
    expect(orchestrator.getMetrics().incompleteAreas).not.toContain(`${url}: authentication_testing`);
    const recovery = command.mission.getTaskQueue().getForMission(mission.id).filter(task => task.executionPlan);
    expect(recovery.map(task => task.executionPlan?.toolName)).toEqual(['web_surface_review', 'xss_scan', 'sqli_scan']);
    expect(recovery.every(task => task.status === 'completed')).toBe(true);
    const snapshot = evaluateCoverage(url, command.arsenal.getOrchestrator().getEvidence());
    for (const capability of VALIDATION_COVERAGE) {
      expect(['completed', 'completed_negative', 'not_applicable']).toContain(snapshot.entries[capability].status);
    }
    expect(paths.some(path => path.startsWith('/search?q='))).toBe(true);
    expect(paths).toContain('/docs'); expect(paths).toContain('/app.js');
    expect(paths).not.toContain('/api/unverified');
    expect(paths.every(path => path === '/' || path === '/api/private' || path === '/docs' || path === '/app.js' || path.startsWith('/search?q='))).toBe(true);
  }, 15000);
});

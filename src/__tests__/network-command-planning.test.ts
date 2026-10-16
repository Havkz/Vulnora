import { describe, expect, it } from 'vitest';
import { Arsenal } from '../arsenal/index.js';
import { basename } from 'node:path';

describe('network command prerequisites', () => {
  function fixture(open: boolean) {
    const arsenal = new Arsenal();
    const calls: Record<string, unknown>[] = [];
    arsenal.register({ name: 'nmap_scan', binary: basename(process.execPath), description: 'Port fixture', category: 'recon', parameters: [],
      handler: async context => {
        calls.push({ ...context.parameters });
        return { success: true, output: open ? '80/tcp open http\n443/tcp closed https' : 'All scanned ports are closed' };
      } });
    return { arsenal, calls };
  }

  it('automatically discovers ports before a service scan and shares concurrent requests', async () => {
    const { arsenal, calls } = fixture(true);
    const results = await Promise.all([0, 1].map(() => arsenal.execute('nmap_scan', {
      parameters: { target: 'fixture.test', ports: '80,443', flags: '-sV --version-light' },
    })));
    expect(results.every(result => result.success), JSON.stringify(results)).toBe(true);
    expect(calls).toEqual([
      { target: 'fixture.test', ports: '80,443', flags: '-sT -Pn --open' },
      { target: 'fixture.test', ports: '80', flags: '-sV --version-light' },
    ]);
    expect(arsenal.getOrchestrator().getEvidence().filter(record => record.status === 'success').map(record => record.toolCategory))
      .toContain('service_detection');
    expect(arsenal.getOrchestrator().getEvents().some(event => event.action === 'BLOCKED')).toBe(false);
    expect(arsenal.getOrchestrator().getBudget('fixture.test').used.port_probe_budget).toBe(3);
  });

  it('treats closed ports as a valid negative result without repeating discovery or attempting service detection', async () => {
    const { arsenal, calls } = fixture(false);
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await arsenal.execute('nmap_scan', { parameters: { target: 'fixture.test', ports: '80,443' } });
      expect(result.success, result.error).toBe(true); expect(result.output).toContain('service detection is not applicable');
    }
    expect(calls).toHaveLength(1);
    expect(arsenal.getOrchestrator().getBudget('fixture.test').used.port_probe_budget).toBe(2);
  });

  it('normalizes a scoped inline port selector before stage selection and accounting', async () => {
    const { arsenal, calls } = fixture(true);
    arsenal.setScope({ allowedHosts: ['fixture.test'], exactHosts: true, allowPrivate: false, allowLoopback: false });
    const result = await arsenal.execute('nmap_scan', { parameters: { target: 'fixture.test', flags: '-sV -p 80,443' } });
    expect(result.success, result.error).toBe(true);
    expect(calls).toEqual([
      { target: 'fixture.test', ports: '80,443', flags: '-sT -Pn --open' },
      { target: 'fixture.test', ports: '80', flags: '-sV' },
    ]);
    expect(arsenal.getOrchestrator().getBudget('fixture.test').used.port_probe_budget).toBe(3);
  });

  it('does not run prerequisites outside scope or during reporting', async () => {
    const { arsenal, calls } = fixture(true);
    arsenal.setScope({ allowedHosts: ['127.0.0.1'], exactHosts: true, allowPrivate: false, allowLoopback: false });
    const denied = await arsenal.execute('nmap_scan', { parameters: { target: '192.0.2.1', flags: '-sV' } });
    expect(denied.metadata?.orchestrationStatus).toBe('scope_denied');
    const report = await arsenal.execute('nmap_scan', { parameters: { target: '127.0.0.1', flags: '-sV' }, purpose: 'reporting' });
    expect(report.success).toBe(false); expect(calls).toHaveLength(0);
  });

  it('charges a top-port request for its actual selection and gates a full scan', async () => {
    const { arsenal, calls } = fixture(true);
    arsenal.setScope({ allowedHosts: ['fixture.test'], exactHosts: true, allowPrivate: false, allowLoopback: false });
    const result = await arsenal.execute('nmap_scan', { parameters: { target: 'fixture.test', flags: '--top-ports=1200 -sT' } });
    expect(result.success, result.error).toBe(true);
    expect(arsenal.getOrchestrator().getBudget('fixture.test').used.port_probe_budget).toBe(1200);
    const full = await arsenal.execute('nmap_scan', { parameters: { target: 'fixture.test', flags: '--top-ports 65535 -sT' } });
    expect(full.success).toBe(false); expect(full.error).toContain('authorization receipt');
    expect(calls).toHaveLength(1);
    const smaller = await arsenal.execute('nmap_scan', { parameters: { target: 'fixture.test', flags: '--top-ports 20 -sT' } });
    expect(smaller.success, smaller.error).toBe(true); expect(calls).toHaveLength(2);
    expect(arsenal.getOrchestrator().getBudget('fixture.test').used.port_probe_budget).toBe(1220);
  });
});

import { expect, it, vi } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Arsenal, EXTERNAL_TOOLS, runSubprocess } from '../arsenal/index.js';

it.skipIf(process.platform === 'win32')('uses increasing Nuclei request counts as progress and stops unchanged heartbeat statistics', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-nuclei-progress-'));
  try {
    const script = "let n=0;setInterval(()=>{console.log(JSON.stringify({requests:process.argv[1]==='advancing'?++n:1,duration:Date.now()}));if(n===8)process.exit(0)},100)";
    await writeFile(join(directory, 'nuclei'), `#!/bin/sh\nexec '${process.execPath}' -e '${script.replace(/'/g, "'\\''")}' "$1"\n`, { mode: 0o700 });
    vi.stubEnv('PATH', directory + ':' + process.env.PATH);
    const advancing = await runSubprocess('nuclei', ['advancing'], { timeout: 400 });
    expect(advancing.exitCode).toBe(0); expect(advancing.stdout).toContain('"requests":8');
    const frozen = await runSubprocess('nuclei', ['frozen'], { timeout: 400 });
    expect(frozen.exitCode).toBe(-1); expect(frozen.stderr).toContain('timeout');
  } finally { vi.unstubAllEnvs(); await rm(directory, { recursive: true, force: true }); }
});

it.skipIf(process.platform === 'win32')('retains parsed Nuclei findings and exact locations when the scanner exits unsuccessfully', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-nuclei-partial-'));
  const line = JSON.stringify({ 'template-id': 'fixture', 'matched-at': 'http://127.0.0.1/fixture-evidence',
    info: { name: 'Fixture exposure', severity: 'high', description: 'Recorded before scanner failure' } });
  try {
    await writeFile(join(directory, 'nuclei'), `#!/bin/sh\nif [ "$1" = "-version" ]; then echo fixture; exit 0; fi\nprintf '%s\\n' '${line.replace(/'/g, "'\\''")}'\necho 'fixture scanner failure' >&2\nexit 1\n`, { mode: 0o700 });
    vi.stubEnv('PATH', directory + ':' + process.env.PATH);
    const arsenal = new Arsenal(); arsenal.registerMany(EXTERNAL_TOOLS.filter(tool => tool.name === 'nuclei_scan'));
    const result = await arsenal.execute('nuclei_scan', { parameters: { target: 'http://127.0.0.1' } });
    expect(result.success).toBe(false); expect(result.error).toContain('fixture scanner failure');
    expect(result.metadata?.partial).toBe(true); expect(result.output).toContain('(incomplete)');
    expect(result.findings).toEqual([expect.objectContaining({ title: 'Fixture exposure', severity: 'high',
      details: 'Fixture exposure at http://127.0.0.1/fixture-evidence: Recorded before scanner failure' })]);
    expect(arsenal.getOrchestrator().getEvidence().at(-1)?.result.findings).toHaveLength(1);
  } finally { vi.unstubAllEnvs(); await rm(directory, { recursive: true, force: true }); }
});

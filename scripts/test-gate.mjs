#!/usr/bin/env node
// test-gate — the live verification gate (the honesty spine, in the engine path).
// A finding cannot be marked verified without real tool-output provenance.
// Requires a build first (imports the compiled dist).
import { gateLiveFinding } from '../dist/evidence/gate.js';

let pass = 0, fail = 0;
const ok = (n, c) => { if (c) pass++; else { fail++; console.log('  ❌', n); } };

ok('prose/screenshot-only finding is REFUSED (no tool output)',
  gateLiveFinding({ severity: 'high', evidence: [{ type: 'screenshot', content: 'looks bad' }] }).passed === false);
ok('zero-evidence critical is REFUSED with provenance=none',
  (() => { const r = gateLiveFinding({ severity: 'critical', evidence: [] }); return r.passed === false && r.provenance === 'none'; })());
ok('output provenance alone does not verify a vulnerability',
  (() => { const r = gateLiveFinding({ severity: 'high', evidence: [{ type: 'output', content: '$ sqlmap … [INFO] back-end DBMS is MySQL' }] }); return r.passed === false && r.provenance === 'tool'; })());
ok('a command alone does not verify a vulnerability',
  gateLiveFinding({ severity: 'medium', evidence: [{ type: 'command', content: 'curl -s http://t/?id=1%27' }] }).passed === false);
ok('the gate states WHY it blocked (honest, not silent)',
  gateLiveFinding({ severity: 'low', evidence: [] }).reasons.length >= 1);

console.log(`\n${fail === 0 ? '✅ SPINE GATE — verification requires matching validated runtime evidence' : '❌ ' + fail + ' FAILED'} — ${pass}/${pass + fail}`);
process.exit(fail === 0 ? 0 : 1);

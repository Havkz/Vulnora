import { describe, expect, it } from 'vitest';
import {
  normalizePortScanTimeout,
  enforceCurlMinimumTimeout,
  isExpectedDnsAbsence,
  isRetryableCurlExit,
  formatDnsRecords,
  normalizeNmapRuntimeFlags,
  parseCurlHeaderLines,
  parsePortSpec,
  resolveCurlProcessTimeoutMs,
  resolveNmapTimeoutMs,
  sanitizeExternalFlags,
} from '../arsenal/index.js';

describe('external tool argument sanitization', () => {
  it('removes dangerous curl flags and their values even when the value is a dash', () => {
    expect(sanitizeExternalFlags('curl', '-sS -D - -o /tmp/out --max-time 20 -i'))
      .toEqual(['-sS', '--max-time', '20', '-i']);
  });

  it('removes attached dangerous curl option values', () => {
    expect(sanitizeExternalFlags('curl', '-D- -o/tmp/out -Kconfig -sS'))
      .toEqual(['-sS']);
  });

  it('preserves commas inside header values and accepts newline-separated headers', () => {
    expect(parseCurlHeaderLines('Accept: text/html,application/xhtml+xml\nUser-Agent: VULNORA'))
      .toEqual(['Accept: text/html,application/xhtml+xml', 'User-Agent: VULNORA']);
  });

  it('splits comma-separated header fields only at a new header name', () => {
    expect(parseCurlHeaderLines('Accept: text/html,application/json, X-Test: yes'))
      .toEqual(['Accept: text/html,application/json', 'X-Test: yes']);
  });
});

describe('scanner timeout normalization', () => {
  it('treats small model-supplied port timeouts as seconds', () => {
    expect(normalizePortScanTimeout(5)).toBe(5000);
    expect(normalizePortScanTimeout(2000)).toBe(2000);
    expect(normalizePortScanTimeout(999999)).toBe(30000);
  });

  it('gives full version scans substantially more time than small scans', () => {
    expect(resolveNmapTimeoutMs(['-sV', '--version-all'], '1-65535')).toBe(30 * 60_000);
    expect(resolveNmapTimeoutMs(['-sV'], '80,443')).toBe(5 * 60_000);
  });

  it('adds finite fast-scan controls to broad ranges but leaves targeted scans alone', () => {
    expect(normalizeNmapRuntimeFlags(['-Pn', '-sT'], '1-65535')).toEqual([
      '-Pn', '-sT', '-T4', '--max-retries', '1', '--min-rate', '500', '--host-timeout', '10m',
    ]);
    expect(normalizeNmapRuntimeFlags(['-sV'], '80,443')).toEqual(['-sV']);
    expect(normalizeNmapRuntimeFlags(['-T3', '--max-retries', '2', '--host-timeout=4m'], '1-20000'))
      .toEqual(['-T3', '--max-retries', '2', '--host-timeout=4m', '--min-rate', '500']);
  });

  it('expands and validates port ranges instead of scanning only the first port', () => {
    expect(parsePortSpec('20-22,80,22')).toEqual([20, 21, 22, 80]);
    expect(parsePortSpec('1-65535')).toHaveLength(65535);
    expect(() => parsePortSpec('0-80')).toThrow(/Invalid port range/);
  });
});

describe('DNS negative-answer classification', () => {
  it('treats absent records as valid results but keeps operational failures as errors', () => {
    expect(isExpectedDnsAbsence(Object.assign(new Error('no data'), { code: 'ENODATA' }))).toBe(true);
    expect(isExpectedDnsAbsence(Object.assign(new Error('not found'), { code: 'ENOTFOUND' }))).toBe(true);
    expect(isExpectedDnsAbsence(Object.assign(new Error('timed out'), { code: 'ETIMEOUT' }))).toBe(false);
  });

  it('formats the object returned by SOA resolution without assuming an array', () => {
    expect(formatDnsRecords('SOA', {
      nsname: 'ns.example', hostmaster: 'hostmaster.example', serial: 42,
      refresh: 10, retry: 20, expire: 30, minttl: 40,
    })).toEqual([
      'nsname=ns.example hostmaster=hostmaster.example serial=42 refresh=10 retry=20 expire=30 minttl=40',
    ]);
  });
});

describe('curl transient transfer handling', () => {
  it('adds or raises curl max-time instead of relying on the shorter subprocess watchdog', () => {
    const absent: string[] = ['-sS', '-i'];
    enforceCurlMinimumTimeout(absent, 120);
    expect(absent).toEqual(['-sS', '-i', '--max-time', '120']);

    const short = ['--max-time', '30'];
    enforceCurlMinimumTimeout(short, 120);
    expect(short).toEqual(['--max-time', '120']);
  });

  it('retries transient DNS/connect/transfer errors but not ordinary HTTP/tool errors', () => {
    for (const code of [6, 7, 18, 28, 35, 52, 56]) expect(isRetryableCurlExit(code)).toBe(true);
    expect(isRetryableCurlExit('18')).toBe(true);
    expect(isRetryableCurlExit(22)).toBe(false);
    expect(isRetryableCurlExit(60)).toBe(false);
  });

  it('keeps the subprocess watchdog beyond curl max-time', () => {
    expect(resolveCurlProcessTimeoutMs(['--max-time', '30'])).toBe(65_000);
    expect(resolveCurlProcessTimeoutMs(['--max-time=60'])).toBe(65_000);
    expect(resolveCurlProcessTimeoutMs(['-m90'])).toBe(95_000);
    expect(resolveCurlProcessTimeoutMs([])).toBe(65_000);
  });
});

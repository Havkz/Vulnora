import { describe, expect, it } from 'vitest';
import { maxToolCallsPerTask } from '../agent/index.js';

describe('agent expensive-tool budget', () => {
  it('bounds repeated port scanners while leaving ordinary tools unrestricted', () => {
    expect(maxToolCallsPerTask('nmap_scan')).toBe(4);
    expect(maxToolCallsPerTask('port_scan')).toBe(4);
    expect(maxToolCallsPerTask('nuclei_scan')).toBe(4);
    expect(maxToolCallsPerTask('curl_request')).toBeUndefined();
  });
});
